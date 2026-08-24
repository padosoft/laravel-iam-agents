<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Padosoft\Iam\Agents\Consent\IamNativeConsentVerifier;
use Padosoft\Iam\Agents\Elevation\DelegationElevationService;
use Padosoft\Iam\Agents\Elevation\ElevationException;
use Padosoft\Iam\Agents\Events\AgentSuspended;
use Padosoft\Iam\Agents\Events\DelegationGrantRevoked;
use Padosoft\Iam\Agents\Http\Controllers\Admin\DelegationGrantsController;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationElevationModel;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Contracts\Assurance\FactorVerifier;
use Padosoft\Iam\Contracts\Delegation\AgentLifecycle;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStore;
use Padosoft\Iam\Contracts\Delegation\ElevationNotifier;
use Padosoft\Iam\Contracts\Delegation\ElevationRequest;
use Padosoft\Iam\Contracts\Identity\SessionMeta;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Identity\Models\User;

uses(RefreshDatabase::class);

/**
 * Mondo elevation: agente attivo con ceiling largo, grant attiva su un sottoinsieme,
 * consenso nativo con fattore fake (codice 123456) e sessione IAM viva.
 *
 * @return array{service: DelegationElevationService, user: SubjectRef, session: mixed, agent: Agent, grant: DelegationGrantModel}
 */
function elevationWorld(): array
{
    config()->set('iam-agents.consent.verifier', IamNativeConsentVerifier::class);
    app()->bind(FactorVerifier::class, fn () => new class implements FactorVerifier
    {
        public function verify(SubjectRef $subject, array $payload): bool
        {
            return ($payload['code'] ?? null) === '123456';
        }
    });

    $user = User::query()->create(['email' => 'delegante@test.it']);
    $subject = new SubjectRef('user', (string) $user->id);
    $session = app(SessionRegistry::class)->start($subject, new SessionMeta);

    $agent = Agent::query()->create([
        'id' => Agent::newId(), 'name' => 'Copilot',
        'max_scopes' => ['orders:read', 'orders:write', 'invoices:read'],
        'status' => AgentStatus::Active->value,
    ]);

    $grant = DelegationGrantModel::query()->create([
        'id' => DelegationGrantModel::newId(),
        'user_type' => $subject->type, 'user_id' => $subject->id,
        'agent_id' => $agent->id,
        'scopes' => ['orders:read'],
        'purpose' => 'Assistenza ordini',
        'status' => DelegationGrantStatus::Active->value,
        'expires_at' => now()->addDay(),
    ]);

    return [
        'service' => app(DelegationElevationService::class),
        'user' => $subject,
        'session' => $session,
        'agent' => $agent,
        'grant' => $grant,
    ];
}

it('request: apre la richiesta pending con i soli scope AGGIUNTIVI, auditata', function () {
    $w = elevationWorld();

    $req = $w['service']->request($w['grant']->id, ['orders:write', 'orders:read'], 'Serve creare la bozza ordine');

    expect($req)->toBeInstanceOf(ElevationRequest::class)
        ->and($req->requestedScopes)->toBe(['orders:write']) // orders:read già coperto
        ->and($req->agentName)->toBe('Copilot');

    $row = DelegationElevationModel::query()->findOrFail($req->id);
    expect($row->status)->toBe(DelegationElevationModel::STATUS_PENDING);

    expect(AuditEvent::query()->where('event_type', 'iam.delegation.elevation.requested')->count())->toBe(1);
});

it('request: scope già coperti, fuori ceiling o grant non attiva ⇒ rifiuto', function () {
    $w = elevationWorld();

    expect(fn () => $w['service']->request($w['grant']->id, ['orders:read'], 'già coperto'))
        ->toThrow(ElevationException::class)
        ->and(fn () => $w['service']->request($w['grant']->id, ['payments:execute'], 'fuori ceiling'))
        ->toThrow(ElevationException::class);

    app(DelegationGrantStore::class)->revoke($w['grant']->id, $w['user']);
    expect(fn () => $w['service']->request($w['grant']->id, ['orders:write'], 'grant revocata'))
        ->toThrow(ElevationException::class);
});

it('approve: RI-consenso step-up bound agli scope extra ⇒ grant estesa, one-shot', function () {
    $w = elevationWorld();
    $req = $w['service']->request($w['grant']->id, ['orders:write'], 'Serve la bozza');

    $challenge = $w['service']->approveChallenge($req->id, $w['user'], $w['session']);
    $w['service']->approve($req->id, $w['user'], $challenge['challenge_id'], ['code' => '123456']);

    $grant = DelegationGrantModel::query()->findOrFail($w['grant']->id);
    expect($grant->scopes)->toBe(['orders:read', 'orders:write']);

    $row = DelegationElevationModel::query()->findOrFail($req->id);
    expect($row->status)->toBe(DelegationElevationModel::STATUS_APPROVED)
        ->and($row->consent_confirmation_id)->not->toBeNull()
        ->and($row->consent_aal)->toBe('aal2');

    // Già decisa: non ri-approvabile (one-shot anche a livello di richiesta).
    expect(fn () => $w['service']->approve($req->id, $w['user'], $challenge['challenge_id'], ['code' => '123456']))
        ->toThrow(ElevationException::class);
});

it('approve: codice errato ⇒ rifiuto senza estendere la grant', function () {
    $w = elevationWorld();
    $req = $w['service']->request($w['grant']->id, ['orders:write'], 'Serve la bozza');
    $challenge = $w['service']->approveChallenge($req->id, $w['user'], $w['session']);

    expect(fn () => $w['service']->approve($req->id, $w['user'], $challenge['challenge_id'], ['code' => '000000']))
        ->toThrow(ElevationException::class);
    expect(DelegationGrantModel::query()->findOrFail($w['grant']->id)->scopes)->toBe(['orders:read']);
});

it('deny è one-click (mai step-up per negare); un altro utente non decide', function () {
    $w = elevationWorld();
    $req = $w['service']->request($w['grant']->id, ['orders:write'], 'Serve la bozza');

    expect(fn () => $w['service']->deny($req->id, new SubjectRef('user', 'intruso')))
        ->toThrow(ElevationException::class);

    $w['service']->deny($req->id, $w['user']);
    expect(DelegationElevationModel::query()->findOrFail($req->id)->status)->toBe(DelegationElevationModel::STATUS_DENIED);
});

it('pending scade da sola: fail-closed, la richiesta ignorata non eleva mai', function () {
    $w = elevationWorld();
    $req = $w['service']->request($w['grant']->id, ['orders:write'], 'Serve la bozza');

    Carbon::setTestNow(now()->addMinutes(16)); // oltre pending_ttl_minutes (15)

    expect(fn () => $w['service']->approveChallenge($req->id, $w['user'], $w['session']))
        ->toThrow(ElevationException::class);
    expect(DelegationElevationModel::query()->findOrFail($req->id)->status)->toBe(DelegationElevationModel::STATUS_EXPIRED);

    Carbon::setTestNow();
});

it('il notifier configurato è best-effort: il fallimento è auditato, la richiesta resta pending', function () {
    $w = elevationWorld();
    config()->set('iam-agents.elevation.notifier', 'configured'); // gate config attivo
    app()->instance(ElevationNotifier::class, new class implements ElevationNotifier
    {
        public function notify(ElevationRequest $request): void
        {
            throw new RuntimeException('all channels down');
        }
    });

    $req = $w['service']->request($w['grant']->id, ['orders:write'], 'Serve la bozza');

    expect(DelegationElevationModel::query()->findOrFail($req->id)->status)->toBe(DelegationElevationModel::STATUS_PENDING);
    $failed = AuditEvent::query()->where('event_type', 'iam.delegation.elevation.notify_failed')->latest('id')->first();
    expect($failed?->metadata_json['error'] ?? null)->toBe('all channels down');
});

it('l\'admin VEDE budget e pending_elevations sulla lista grants (kill-switch context)', function () {
    $w = elevationWorld();
    DelegationGrantModel::query()->whereKey($w['grant']->id)
        ->update(['budget' => json_encode(['amount' => 25.0, 'currency' => 'EUR'])]);
    $req = $w['service']->request($w['grant']->id, ['orders:write'], 'Serve la bozza');

    $controller = new DelegationGrantsController(
        app(DelegationGrantStore::class),
    );
    $payload = $controller->index(Request::create('/', 'GET'))->getData(true);

    $row = collect($payload['data'])->firstWhere('id', $w['grant']->id);
    expect($row['budget'])->toEqual(['amount' => 25, 'currency' => 'EUR'])
        ->and($row['pending_elevations'])->toHaveCount(1)
        ->and($row['pending_elevations'][0]['id'])->toBe($req->id)
        ->and($row['pending_elevations'][0]['requested_scopes'])->toBe(['orders:write'])
        ->and($row['pending_elevations'][0]['reason'])->toBe('Serve la bozza');

    // Decisa ⇒ sparisce dalle pending (il contesto resta pulito).
    $w['service']->deny($req->id, $w['user']);
    $payload = $controller->index(Request::create('/', 'GET'))->getData(true);
    expect(collect($payload['data'])->firstWhere('id', $w['grant']->id)['pending_elevations'])->toBe([]);
});

// ── Lifecycle port + eventi ──

it('AgentLifecycle::suspend è idempotente, auditato e dispatcha AgentSuspended', function () {
    $w = elevationWorld();
    Event::fake([AgentSuspended::class]);

    $port = app(AgentLifecycle::class);
    $port->suspend(new SubjectRef('agent', $w['agent']->id), 'delegation_exchange_burst', 'rebel-ai-guard');

    expect(Agent::query()->findOrFail($w['agent']->id)->status)->toBe(AgentStatus::Suspended->value);
    Event::assertDispatchedTimes(AgentSuspended::class, 1);

    // Idempotente: seconda suspend = no-op (nessun secondo evento), ignoto = no-op.
    $port->suspend(new SubjectRef('agent', $w['agent']->id), 'again', 'rebel-ai-guard');
    $port->suspend(new SubjectRef('agent', 'agt_ignoto'), 'x', 'rebel-ai-guard');
    Event::assertDispatchedTimes(AgentSuspended::class, 1);
});

it('la revoca della grant dispatcha DelegationGrantRevoked col VO completo', function () {
    $w = elevationWorld();
    Event::fake([DelegationGrantRevoked::class]);

    app(DelegationGrantStore::class)->revoke($w['grant']->id, $w['user']);

    Event::assertDispatched(DelegationGrantRevoked::class, function (DelegationGrantRevoked $e) use ($w): bool {
        return $e->grant->id === $w['grant']->id
            && $e->agentName === 'Copilot'
            && $e->grant->status === DelegationGrantStatus::Revoked
            && $e->grant->revokedBy !== null;
    });
});
