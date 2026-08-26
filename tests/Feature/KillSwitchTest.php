<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Padosoft\Iam\Agents\Elevation\DelegationElevationService;
use Padosoft\Iam\Agents\Elevation\ElevationException;
use Padosoft\Iam\Agents\Events\DelegationFrozen;
use Padosoft\Iam\Agents\Events\DelegationUnfrozen;
use Padosoft\Iam\Agents\Freeze\DelegationFreezeService;
use Padosoft\Iam\Agents\Freeze\DelegationFrozenException;
use Padosoft\Iam\Agents\Freeze\FreezeException;
use Padosoft\Iam\Agents\Freeze\FreezeScope;
use Padosoft\Iam\Agents\Http\Controllers\Admin\DelegationFreezesController;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationFreezeModel;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Agents\Pdp\DelegatedEngine;
use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Contracts\Delegation\ActorRef;
use Padosoft\Iam\Contracts\Delegation\AgentRegistry;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationChain;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStore;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;

uses(RefreshDatabase::class);

/**
 * Kill switch asimmetrico: UNO ferma, MOLTI ripartono.
 *
 * I test qui sotto pinnano le tre decisioni che rendono la feature quello che è,
 * e non un flag booleano su una tabella:
 *
 *  - il quorum è fotografato al freeze (chi tocca la config dopo non se lo abbassa);
 *  - il quorum è di identità DISTINTE (lo stesso admin non fa quorum da solo);
 *  - la revoca NON è mai bloccata dal freeze (il kill switch non deve impedire la
 *    risposta all'incidente che lo ha causato).
 */
function frozenAgent(?string $organizationId = null): Agent
{
    return Agent::query()->create([
        'id' => Agent::newId(),
        'name' => 'Copilot',
        'max_scopes' => ['orders:read', 'orders:write'],
        'status' => AgentStatus::Active->value,
        'organization_id' => $organizationId,
    ]);
}

function killSwitch(): DelegationFreezeService
{
    return app(DelegationFreezeService::class);
}

function admin(string $id): SubjectRef
{
    return new SubjectRef('user', $id);
}

it('un solo admin congela: nessuna approvazione, effetto immediato', function () {
    Event::fake([DelegationFrozen::class]);
    $agent = frozenAgent();

    $freeze = killSwitch()->freeze(FreezeScope::Global, null, 'Exfiltration sospetta', admin('alice'));

    expect($freeze->isActive())->toBeTrue()
        ->and($freeze->frozen_by)->toBe('user:alice')
        ->and(killSwitch()->activeFor($agent->id)?->id)->toBe($freeze->id);
    Event::assertDispatched(DelegationFrozen::class);
});

it('un freeze senza motivo è rifiutato: senza, nessuno sa quando toglierlo', function () {
    expect(fn () => killSwitch()->freeze(FreezeScope::Global, null, '   ', admin('alice')))
        ->toThrow(FreezeException::class);
});

it('un freeze di scope agent/organization richiede il target', function () {
    expect(fn () => killSwitch()->freeze(FreezeScope::Agent, null, 'x', admin('alice')))->toThrow(FreezeException::class)
        ->and(fn () => killSwitch()->freeze(FreezeScope::Organization, '', 'x', admin('alice')))->toThrow(FreezeException::class);
});

it('congelare due volte lo stesso scope non crea due freeze da sbloccare', function () {
    // Premere due volte il pulsante durante un incidente è un riflesso normale.
    $first = killSwitch()->freeze(FreezeScope::Global, null, 'Incidente', admin('alice'));
    $second = killSwitch()->freeze(FreezeScope::Global, null, 'Incidente (ancora)', admin('bob'));

    expect($second->id)->toBe($first->id)
        ->and(DelegationFreezeModel::query()->count())->toBe(1);
});

it('il quorum è di admin DISTINTI: lo stesso che approva due volte non sblocca', function () {
    config()->set('iam-agents.kill_switch.lift_quorum', 2);
    $freeze = killSwitch()->freeze(FreezeScope::Global, null, 'Incidente', admin('alice'));

    $first = killSwitch()->approveLift($freeze->id, admin('bob'));
    $repeat = killSwitch()->approveLift($freeze->id, admin('bob'));

    expect($first->lifted)->toBeFalse()->and($first->remaining())->toBe(1)
        ->and($repeat->lifted)->toBeFalse()
        ->and($repeat->alreadyApproved)->toBeTrue()
        ->and($repeat->collected)->toBe(1)
        ->and($freeze->fresh()?->isActive())->toBeTrue();
});

it('raggiunto il quorum la delega riparte, e chi ha congelato conta come chiunque altro', function () {
    // Escludere il freezer non aggiungerebbe sicurezza — l'attaccante che vuole
    // scongelare non è quello che ha congelato — e toglierebbe una firma proprio
    // a chi sta gestendo l'incidente.
    Event::fake([DelegationUnfrozen::class]);
    config()->set('iam-agents.kill_switch.lift_quorum', 2);
    $agent = frozenAgent();
    $freeze = killSwitch()->freeze(FreezeScope::Global, null, 'Incidente', admin('alice'));

    killSwitch()->approveLift($freeze->id, admin('alice'));
    $outcome = killSwitch()->approveLift($freeze->id, admin('bob'));

    expect($outcome->lifted)->toBeTrue()
        ->and($outcome->collected)->toBe(2)
        ->and($freeze->fresh()?->lifted_by)->toBe('user:bob')
        ->and(killSwitch()->activeFor($agent->id))->toBeNull();
    Event::assertDispatched(DelegationUnfrozen::class);
});

it('il quorum è FOTOGRAFATO al freeze: abbassarlo dopo non sblocca da soli', function () {
    // La decisione portante dell'intera feature. Se il quorum si rileggesse dalla
    // config allo sblocco, chi può modificare la config lo porta a 1 e scongela
    // da solo — e un controllo aggirabile da chi si sta difendendo non è un
    // controllo.
    config()->set('iam-agents.kill_switch.lift_quorum', 3);
    $freeze = killSwitch()->freeze(FreezeScope::Global, null, 'Incidente', admin('alice'));

    config()->set('iam-agents.kill_switch.lift_quorum', 1);

    $outcome = killSwitch()->approveLift($freeze->id, admin('mallory'));

    expect($freeze->required_quorum)->toBe(3)
        ->and($outcome->lifted)->toBeFalse()
        ->and($outcome->remaining())->toBe(2);
});

it('un freeze già rimosso non si approva una seconda volta', function () {
    config()->set('iam-agents.kill_switch.lift_quorum', 1);
    $freeze = killSwitch()->freeze(FreezeScope::Global, null, 'Incidente', admin('alice'));
    killSwitch()->approveLift($freeze->id, admin('bob'));

    expect(fn () => killSwitch()->approveLift($freeze->id, admin('carol')))->toThrow(FreezeException::class);
});

it('lo scope agent ferma UN agente e lascia lavorare gli altri', function () {
    $target = frozenAgent();
    $other = frozenAgent();

    killSwitch()->freeze(FreezeScope::Agent, $target->id, 'Comportamento anomalo', admin('alice'));

    expect(killSwitch()->activeFor($target->id))->not->toBeNull()
        ->and(killSwitch()->activeFor($other->id))->toBeNull();
});

it("lo scope organization ferma gli agenti dell'org risolvendola dall'agente", function () {
    // Il PDP delegato conosce l'agente, non la sua organizzazione: il claim `act`
    // porta l'uno e non l'altra. L'org viene risolta solo quando esiste davvero
    // un freeze di scope organization.
    $inside = frozenAgent('org-1');
    $outside = frozenAgent('org-2');

    killSwitch()->freeze(FreezeScope::Organization, 'org-1', 'Tenant compromesso', admin('alice'));

    expect(killSwitch()->activeFor($inside->id)?->scope)->toBe('organization')
        ->and(killSwitch()->activeFor($outside->id))->toBeNull();
});

it('davanti a più freeze riporta il più ampio', function () {
    $agent = frozenAgent();
    killSwitch()->freeze(FreezeScope::Agent, $agent->id, 'Agente', admin('alice'));
    killSwitch()->freeze(FreezeScope::Global, null, 'Tutto', admin('alice'));

    expect(killSwitch()->activeFor($agent->id)?->scope)->toBe('global');
});

it('il PDP delegato nega mentre la delega è congelata', function () {
    // Il punto che rende il freeze un vero kill switch: i token già emessi restano
    // validi fino a scadenza, ma da qui in poi non decidono più nulla.
    $agent = frozenAgent();
    $user = new SubjectRef('user', 'u1');
    $chain = new DelegationChain(ActorRef::fromAgentId($agent->id));

    $engine = new DelegatedEngine(
        new class implements AuthorizationEngine
        {
            public function check(array $query): array
            {
                return ['allowed' => true, 'decision_id' => 'dec_fake', 'policy_version' => 1];
            }

            public function listSubjects(string $relation, string $objectType, string $objectId): iterable
            {
                return [];
            }

            public function listResources(SubjectRef $subject, string $relation): iterable
            {
                return [];
            }
        },
        app(AgentRegistry::class),
        app(DelegationGrantStore::class),
        killSwitch(),
    );

    expect($engine->checkDelegated($user, $chain, ['permission' => 'orders.read'])['allowed'])->toBeTrue();

    killSwitch()->freeze(FreezeScope::Global, null, 'Incidente', admin('alice'));

    $decision = $engine->checkDelegated($user, $chain, ['permission' => 'orders.read']);

    expect($decision['allowed'])->toBeFalse()
        ->and($decision['reason'])->toBe(DelegationFrozenException::REASON_FROZEN);
});

it('una flotta congelata non allarga i propri scope', function () {
    $agent = frozenAgent();
    $grant = DelegationGrantModel::query()->create([
        'id' => DelegationGrantModel::newId(),
        'user_type' => 'user', 'user_id' => 'u1',
        'agent_id' => $agent->id,
        'scopes' => ['orders:read'],
        'purpose' => 'Assistenza',
        'status' => DelegationGrantStatus::Active->value,
        'expires_at' => now()->addDay(),
    ]);

    killSwitch()->freeze(FreezeScope::Global, null, 'Incidente', admin('alice'));

    expect(fn () => app(DelegationElevationService::class)->request($grant->id, ['orders:write'], 'Serve scrivere'))
        ->toThrow(ElevationException::class);
});

it('la revoca NON è bloccata dal freeze', function () {
    // Se congelare bloccasse anche revocare, il kill switch impedirebbe la
    // risposta all'incidente che lo ha causato.
    $agent = frozenAgent();
    $grant = DelegationGrantModel::query()->create([
        'id' => DelegationGrantModel::newId(),
        'user_type' => 'user', 'user_id' => 'u1',
        'agent_id' => $agent->id,
        'scopes' => ['orders:read'],
        'purpose' => 'Assistenza',
        'status' => DelegationGrantStatus::Active->value,
        'expires_at' => now()->addDay(),
    ]);

    killSwitch()->freeze(FreezeScope::Global, null, 'Incidente', admin('alice'));
    app(DelegationGrantStore::class)->revoke($grant->id, admin('alice'));

    expect($grant->fresh()?->status)->toBe(DelegationGrantStatus::Revoked->value);
});

it('freeze, approvazioni e sblocco finiscono tutti nello stream delegation', function () {
    config()->set('iam-agents.kill_switch.lift_quorum', 2);
    $freeze = killSwitch()->freeze(FreezeScope::Global, null, 'Incidente', admin('alice'));
    killSwitch()->approveLift($freeze->id, admin('alice'));
    killSwitch()->approveLift($freeze->id, admin('bob'));

    $types = AuditEvent::query()->where('stream', 'delegation')->pluck('event_type')->all();

    expect($types)->toContain('iam.delegation.freeze.applied')
        ->and($types)->toContain('iam.delegation.freeze.lift_approved')
        ->and($types)->toContain('iam.delegation.freeze.lifted');
});

it('admin API: congela, mostra quante firme mancano, e sblocca al quorum', function () {
    config()->set('iam-agents.kill_switch.lift_quorum', 2);
    $controller = app(DelegationFreezesController::class);

    $created = $controller->store(Request::create('/', 'POST', [
        'scope' => 'global', 'reason' => 'Incidente', 'frozen_by' => 'alice',
    ]));
    expect($created->getStatusCode())->toBe(201);

    /** @var array<string, mixed> $body */
    $body = json_decode((string) $created->getContent(), true);
    $id = $body['data']['id'];

    expect($body['data']['required_quorum'])->toBe(2)
        ->and($body['data']['remaining_approvals'])->toBe(2);

    $controller->approveLift(Request::create('/', 'POST', ['approver' => 'bob']), $id);

    /** @var array<string, mixed> $shown */
    $shown = json_decode((string) $controller->show($id)->getContent(), true);
    expect($shown['data']['remaining_approvals'])->toBe(1)
        ->and($shown['data']['approvals'])->toHaveCount(1);

    $second = $controller->approveLift(Request::create('/', 'POST', ['approver' => 'carol']), $id);
    /** @var array<string, mixed> $lifted */
    $lifted = json_decode((string) $second->getContent(), true);

    expect($lifted['data']['lifted'])->toBeTrue()
        ->and(DelegationFreezeModel::query()->find($id)?->isActive())->toBeFalse();
});

it('admin API: uno scope inesistente è 422, non un freeze silenziosamente globale', function () {
    $response = app(DelegationFreezesController::class)->store(Request::create('/', 'POST', [
        'scope' => 'everything', 'reason' => 'x',
    ]));

    expect($response->getStatusCode())->toBe(422)
        ->and(DelegationFreezeModel::query()->count())->toBe(0);
});
