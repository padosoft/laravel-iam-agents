<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Agents\Governance\DelegationGrantReviewableSource;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Agents\Models\DelegationReceiptModel;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStatus;
use Padosoft\Iam\Domain\Governance\Reviews\CampaignEngine;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewItem;
use Padosoft\Iam\Domain\Governance\Reviews\Reviewable\ReviewableRegistry;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

uses(RefreshDatabase::class);

/**
 * Le delegation grant dentro l'IGA del server.
 *
 * Il punto di questi test non è "la sorgente elenca righe": è che una delega dimenticata **si
 * vede** (dormant, agente sospeso, scadenza), che la revoca del reviewer passa davvero dallo
 * store (audit + evento, non un UPDATE nudo), e che una campagna di tenant non tocca le deleghe
 * di un altro.
 */
function reviewAgent(array $overrides = []): Agent
{
    return Agent::query()->create(array_merge([
        'id' => Agent::newId(),
        'name' => 'CRM Agent',
        'max_scopes' => ['orders:read', 'orders:draft'],
        'status' => AgentStatus::Active->value,
    ], $overrides));
}

function reviewDelegation(Agent $agent, array $overrides = []): DelegationGrantModel
{
    return DelegationGrantModel::query()->create(array_merge([
        'id' => DelegationGrantModel::newId(),
        'user_type' => 'user',
        'user_id' => 'usr_42',
        'agent_id' => $agent->id,
        'scopes' => ['orders:read'],
        'purpose' => 'Bozze ordini',
        'status' => DelegationGrantStatus::Active->value,
        'expires_at' => now()->addDays(20),
    ], $overrides));
}

function delegationCampaign(array $overrides = []): ReviewCampaign
{
    return ReviewCampaign::create(array_merge([
        'name' => 'Delegation review',
        'on_unconfirmed' => 'revoke',
        'scope_json' => ['reviewable_types' => ['delegation_grant']],
    ], $overrides));
}

function source(): DelegationGrantReviewableSource
{
    $source = app(ReviewableRegistry::class)->for('delegation_grant');
    expect($source)->toBeInstanceOf(DelegationGrantReviewableSource::class);

    return $source;
}

it('il modulo registra la propria sorgente nel registro del server', function () {
    expect(app(ReviewableRegistry::class)->types())->toContain('delegation_grant')
        ->and(source()->label())->toBe('Delegation grants');
});

it('una campagna che include delegation_grant genera un item per ogni delega attiva', function () {
    $agent = reviewAgent();
    $live = reviewDelegation($agent);
    reviewDelegation($agent, ['status' => DelegationGrantStatus::Revoked->value]); // già revocata
    reviewDelegation($agent, ['expires_at' => now()->subDay()]);                    // scaduta

    $c = delegationCampaign();

    expect(app(CampaignEngine::class)->open($c))->toBe(1);

    $item = ReviewItem::query()->firstOrFail();
    expect($item->reviewable_type)->toBe('delegation_grant')
        ->and($item->reviewable_id)->toBe($live->id);
});

it('il delegante è il reviewer naturale della propria delega', function () {
    // È lui che ha dato il consenso, ed è lui che sa se l'agente serve ancora.
    reviewDelegation(reviewAgent());
    $c = delegationCampaign();
    app(CampaignEngine::class)->open($c);

    expect(ReviewItem::query()->firstOrFail()->reviewer_subject)->toBe('user:usr_42');
});

it('una strategia named scavalca il delegante (un audit centralizzato deve poterlo fare)', function () {
    reviewDelegation(reviewAgent());
    $c = delegationCampaign(['scope_json' => [
        'reviewable_types' => ['delegation_grant'],
        'reviewer' => 'user:compliance',
    ]]);
    app(CampaignEngine::class)->open($c);

    expect(ReviewItem::query()->firstOrFail()->reviewer_subject)->toBe('user:compliance');
});

it('una delega mai usata è segnalata come dormiente', function () {
    reviewDelegation(reviewAgent());
    $c = delegationCampaign();
    app(CampaignEngine::class)->open($c);

    $signals = ReviewItem::query()->firstOrFail()->signals_json;
    expect($signals['never_used'])->toBeTrue()
        ->and($signals['dormant'])->toBeTrue()
        ->and($signals['last_used_days'])->toBeNull()
        ->and($signals['expires_in_days'])->toBeGreaterThan(0);
});

it('l\'ultimo uso viene dalle ricevute firmate, non da un campo inventato', function () {
    $agent = reviewAgent();
    $grant = reviewDelegation($agent);
    DelegationReceiptModel::query()->create([
        'id' => 'rcp_'.uniqid(),
        'grant_id' => $grant->id,
        'agent_id' => $agent->id,
        'subject_type' => 'user',
        'subject_id' => 'usr_42',
        'action' => 'orders.draft',
        'outcome' => 'success',
        'issued_at' => now()->subDays(3),
        'jws' => 'header.payload.signature',
        'payload_digest' => str_repeat('a', 64),
    ]);

    $c = delegationCampaign();
    app(CampaignEngine::class)->open($c);

    $signals = ReviewItem::query()->firstOrFail()->signals_json;
    expect($signals['never_used'])->toBeFalse()
        ->and($signals['last_used_days'])->toBe(3)
        ->and($signals['dormant'])->toBeFalse();
});

it('una delega verso un agente sospeso è segnalata: è il caso da chiudere per primo', function () {
    // Se l'agente torna attivo, la delega torna viva senza che nessuno l'abbia riconfermata.
    $agent = reviewAgent(['status' => AgentStatus::Suspended->value]);
    reviewDelegation($agent);
    $c = delegationCampaign();
    app(CampaignEngine::class)->open($c);

    $signals = ReviewItem::query()->firstOrFail()->signals_json;
    expect($signals['agent_suspended'])->toBeTrue()
        ->and($signals['agent_status'])->toBe(AgentStatus::Suspended->value);
});

it('la revoca del reviewer passa dallo store: la grant muore e l\'evento parte', function () {
    $grant = reviewDelegation(reviewAgent());
    $c = delegationCampaign();
    $engine = app(CampaignEngine::class);
    $engine->open($c);

    $item = ReviewItem::query()->firstOrFail();
    $engine->decide($item, 'revoked', 'user:compliance', 'non più necessaria');

    expect($grant->fresh()->status)->toBe(DelegationGrantStatus::Revoked->value)
        ->and($grant->fresh()->revoked_at)->not->toBeNull()
        ->and($grant->fresh()->revoked_by_id)->toBe('compliance')
        ->and($item->fresh()->decision)->toBe('revoked');
});

it('close con on_unconfirmed=revoke chiude le deleghe non confermate', function () {
    $grant = reviewDelegation(reviewAgent());
    $c = delegationCampaign();
    $engine = app(CampaignEngine::class);
    $engine->open($c);

    expect($engine->close($c))->toBe(1)
        ->and($grant->fresh()->status)->toBe(DelegationGrantStatus::Revoked->value);
});

it('approvare una delega non la tocca', function () {
    $grant = reviewDelegation(reviewAgent());
    $c = delegationCampaign();
    $engine = app(CampaignEngine::class);
    $engine->open($c);

    $engine->decide(ReviewItem::query()->firstOrFail(), 'approved', 'user:compliance');

    expect($grant->fresh()->status)->toBe(DelegationGrantStatus::Active->value)
        ->and($grant->fresh()->revoked_at)->toBeNull();
});

it('revocare due volte è idempotente (la sorgente non esplode né riaudita)', function () {
    $grant = reviewDelegation(reviewAgent());

    expect(source()->revoke($grant->id, 'user:compliance', 'prima'))->toBeTrue()
        ->and(source()->revoke($grant->id, 'user:compliance', 'seconda'))->toBeFalse()
        ->and(source()->revoke('dgr_inesistente', 'user:compliance', 'assente'))->toBeFalse();
});

it('una campagna di tenant non certifica le deleghe verso agenti di un altro tenant', function () {
    $org1 = Organization::create(['name' => 'Org 1', 'key' => 'org-1']);
    $org2 = Organization::create(['name' => 'Org 2', 'key' => 'org-2']);
    $mine = reviewAgent(['organization_id' => $org1->id]);
    $theirs = reviewAgent(['organization_id' => $org2->id]);
    $ours = reviewDelegation($mine);
    reviewDelegation($theirs);

    $c = delegationCampaign(['organization_id' => $org1->id]);

    expect(app(CampaignEngine::class)->open($c))->toBe(1)
        ->and(ReviewItem::query()->firstOrFail()->reviewable_id)->toBe($ours->id);
});

it('agent_ids restringe la campagna a specifici agenti', function () {
    $a = reviewAgent(['name' => 'A']);
    $b = reviewAgent(['name' => 'B']);
    $target = reviewDelegation($a);
    reviewDelegation($b);

    $c = delegationCampaign(['scope_json' => [
        'reviewable_types' => ['delegation_grant'],
        'agent_ids' => [$a->id],
    ]]);

    expect(app(CampaignEngine::class)->open($c))->toBe(1)
        ->and(ReviewItem::query()->firstOrFail()->reviewable_id)->toBe($target->id);
});

it('describeMany dà al console i campi comuni PIÙ quelli propri della delega', function () {
    $agent = reviewAgent(['application_key' => 'crm']);
    $grant = reviewDelegation($agent);

    $described = source()->describeMany([$grant->id]);

    expect($described[$grant->id])->toMatchArray([
        // Nomi condivisi con i grant RBAC: il console rende una riga sola per entrambi i tipi.
        'subject_type' => 'user',
        'subject_id' => 'usr_42',
        'privilege_type' => 'delegation',
        'privilege_key' => 'orders:read',
        'application_key' => 'crm',
        'effect' => 'permit',
        // Campi propri della delega.
        'agent_id' => $agent->id,
        'agent_name' => 'CRM Agent',
        'purpose' => 'Bozze ordini',
        'grant_status' => DelegationGrantStatus::Active->value,
    ]);
});

it('describeMany su una lista vuota non interroga il database', function () {
    expect(source()->describeMany([]))->toBe([]);
});
