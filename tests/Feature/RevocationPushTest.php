<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Padosoft\Iam\Agents\Audit\DelegationAudit;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStatus;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookDelivery;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookSubscription;

uses(RefreshDatabase::class);

/**
 * P2 lato modulo: gli eventi dello stream `delegation` passano dall'AuditRecorder del
 * server, quindi una revoca di grant viene SPINTA alle subscription webhook attive —
 * il push di revoca verso PEP e agent, senza attendere un poll.
 */
function pushGrantRow(): DelegationGrantModel
{
    $agent = Agent::query()->create([
        'id' => Agent::newId(),
        'name' => 'Rev Push', 'max_scopes' => ['orders:read'],
        'status' => AgentStatus::Active->value,
        'owner_type' => 'user', 'owner_id' => 'u-owner',
    ]);

    return DelegationGrantModel::query()->create([
        'id' => DelegationGrantModel::newId(),
        'user_type' => 'user', 'user_id' => 'u42',
        'agent_id' => $agent->id,
        'scopes' => ['orders:read'],
        'purpose' => 'Assistenza ordini',
        'status' => DelegationGrantStatus::Active->value,
        'expires_at' => now()->addDays(7),
    ]);
}

it('una revoca di grant viene spinta alle subscription webhook (stream delegation)', function () {
    Http::fake(['https://pep.test/*' => Http::response('', 200)]);
    $sub = new WebhookSubscription;
    $sub->fill([
        'organization_id' => null, // subscription globale: gli eventi delegation qui non hanno org
        'url' => 'https://pep.test/revocations',
        'secret_encrypted' => app(SecretCipher::class)->encrypt('whsec_pep'),
        'event_filters' => ['iam.delegation.*'],
    ]);
    $sub->save();

    $grant = pushGrantRow();
    app(DelegationAudit::class)->grantRevoked($grant, new SubjectRef('user', 'u42'));

    Http::assertSentCount(1);
    Http::assertSent(fn ($request) => str_contains($request->body(), 'iam.delegation.grant.revoked')
        && str_contains($request->body(), $grant->id));
    expect(WebhookDelivery::query()->where('status', 'delivered')->count())->toBe(1)
        ->and(AuditEvent::query()->where('event_type', 'iam.delegation.grant.revoked')->count())->toBe(1);
});

it('il push resta best-effort: revoca auditata anche senza subscription', function () {
    Http::fake();
    $grant = pushGrantRow();

    app(DelegationAudit::class)->grantRevoked($grant, new SubjectRef('user', 'u42'));

    Http::assertNothingSent();
    expect(AuditEvent::query()->where('event_type', 'iam.delegation.grant.revoked')->count())->toBe(1);
});

it('il modulo si dichiara a GET /capabilities (P4)', function () {
    expect(config('iam.capabilities.modules.agents'))->toBeTrue()
        ->and(config('iam.capabilities.features.agents.registration'))->toBeFalse()
        ->and(config('iam.capabilities.features.agents.max_delegation_depth'))->toBe(1);
});
