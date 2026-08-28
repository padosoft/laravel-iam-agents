<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Agents\Models\Agent;
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

uses(RefreshDatabase::class);

/**
 * Intersection rule: autorità effettiva = utente ∩ agente, MAI l'unione.
 * L'engine interno è un fake deterministico (allow per-soggetto configurabile);
 * registry e store sono quelli veri su DB.
 */
function fakeEngine(array $allowedSubjects): AuthorizationEngine
{
    return new class($allowedSubjects) implements AuthorizationEngine
    {
        public function __construct(private readonly array $allowed) {}

        public function check(array $query): array
        {
            $subject = $query['subject'] ?? [];
            $key = ($subject['type'] ?? '').':'.($subject['id'] ?? '');

            return [
                'allowed' => in_array($key, $this->allowed, true),
                'decision_id' => 'dec_fake_'.substr(md5($key), 0, 8),
                'policy_version' => 7,
            ];
        }

        public function listSubjects(string $relation, string $objectType, string $objectId): iterable
        {
            return [];
        }

        public function listResources(SubjectRef $subject, string $relation): iterable
        {
            return [];
        }
    };
}

function activeAgentRow(): Agent
{
    return Agent::query()->create([
        'id' => Agent::newId(),
        'name' => 'A', 'max_scopes' => ['orders:read'],
        'status' => AgentStatus::Active->value,
    ]);
}

function engineWith(array $allowedSubjects): DelegatedEngine
{
    return new DelegatedEngine(
        fakeEngine($allowedSubjects),
        app(AgentRegistry::class),
        app(DelegationGrantStore::class),
    );
}

it('permette SOLO quando entrambi i layer permettono (intersezione, mai unione)', function () {
    $agent = activeAgentRow();
    $user = new SubjectRef('user', 'u1');
    $chain = new DelegationChain(ActorRef::fromAgentId($agent->id));
    $query = ['permission' => 'orders.read'];

    // Entrambi ⇒ allow. Solo utente, solo agente, nessuno ⇒ deny.
    expect(engineWith(['user:u1', 'agent:'.$agent->id])->checkDelegated($user, $chain, $query)['allowed'])->toBeTrue()
        ->and(engineWith(['user:u1'])->checkDelegated($user, $chain, $query)['allowed'])->toBeFalse()
        ->and(engineWith(['agent:'.$agent->id])->checkDelegated($user, $chain, $query)['allowed'])->toBeFalse()
        ->and(engineWith([])->checkDelegated($user, $chain, $query)['allowed'])->toBeFalse();
});

it('cita ENTRAMBI i soggetti: actors + sub_decisions per layer', function () {
    $agent = activeAgentRow();
    $decision = engineWith(['user:u1', 'agent:'.$agent->id])->checkDelegated(
        new SubjectRef('user', 'u1'),
        new DelegationChain(ActorRef::fromAgentId($agent->id)),
        ['permission' => 'orders.read'],
    );

    expect($decision['actors'])->toBe(['agent:'.$agent->id])
        ->and($decision['sub_decisions']['subject'])->not->toBeNull()
        ->and($decision['sub_decisions']['actor'])->not->toBeNull()
        ->and($decision['decision_id'])->toStartWith('dec_');
});

it('agente ignoto o non attivo ⇒ deny agent_not_active SENZA interrogare l\'engine', function () {
    $user = new SubjectRef('user', 'u1');

    // Ignoto (mai registrato).
    $unknown = engineWith(['user:u1'])->checkDelegated($user, new DelegationChain(ActorRef::fromAgentId('agt_ghost')), []);
    expect($unknown['allowed'])->toBeFalse()->and($unknown['reason'])->toBe('agent_not_active');

    // Registrato ma suspended.
    $agent = activeAgentRow();
    $agent->fill(['status' => AgentStatus::Suspended->value])->save();
    $suspended = engineWith(['user:u1', 'agent:'.$agent->id])
        ->checkDelegated($user, new DelegationChain(ActorRef::fromAgentId($agent->id)), []);
    expect($suspended['allowed'])->toBeFalse()->and($suspended['reason'])->toBe('agent_not_active');
});

it('con pds_dgr nel query la grant deve essere attiva e coerente (revoca istantanea)', function () {
    $agent = activeAgentRow();
    $user = new SubjectRef('user', 'u1');
    $chain = new DelegationChain(ActorRef::fromAgentId($agent->id));
    $engine = engineWith(['user:u1', 'agent:'.$agent->id]);

    $grant = DelegationGrantModel::query()->create([
        'id' => DelegationGrantModel::newId(),
        'user_type' => 'user', 'user_id' => 'u1',
        'agent_id' => $agent->id,
        'scopes' => ['orders:read'], 'purpose' => 'test',
        'status' => DelegationGrantStatus::Active->value,
        'expires_at' => now()->addDay(),
    ]);

    expect($engine->checkDelegated($user, $chain, ['delegation_grant_id' => $grant->id])['allowed'])->toBeTrue();

    // Revoca ⇒ deny immediato al check successivo (nessuna attesa di scadenza token).
    app(DelegationGrantStore::class)->revoke($grant->id, $user);
    $denied = $engine->checkDelegated($user, $chain, ['delegation_grant_id' => $grant->id]);
    expect($denied['allowed'])->toBeFalse()->and($denied['reason'])->toBe('delegation_grant_not_active');

    // Grant di un ALTRO utente ⇒ deny (coerenza della coppia).
    $other = $engine->checkDelegated(new SubjectRef('user', 'u2'), $chain, ['delegation_grant_id' => $grant->id]);
    expect($other['allowed'])->toBeFalse();
});

it('il check single-subject resta intatto (decorator trasparente)', function () {
    $engine = engineWith(['user:u1']);

    expect($engine->check(['subject' => ['type' => 'user', 'id' => 'u1']])['allowed'])->toBeTrue()
        ->and($engine->check(['subject' => ['type' => 'user', 'id' => 'u2']])['allowed'])->toBeFalse();
});

/*
|--------------------------------------------------------------------------
| Multi-hop: l'intersezione deve valere su OGNI anello della catena
|--------------------------------------------------------------------------
*/

it('nega quando un hop NON corrente non e\' autorizzato, non solo quello corrente', function () {
    // Catena: $current agisce per delega ricevuta da $root (actors[0] = corrente).
    // L'utente puo', il corrente puo', ma la RADICE no. Se il PDP guardasse solo
    // l'attore corrente questa passerebbe: sarebbe la delega usata per GUADAGNARE
    // autorita' che la radice non ha. E' il caso che rende il multi-hop pericoloso
    // se implementato male, ed e' il test che falliva prima di questo fix.
    $root = activeAgentRow();
    $current = activeAgentRow();
    $chain = new DelegationChain(ActorRef::fromAgentId($current->id), ActorRef::fromAgentId($root->id));

    $decision = engineWith(['user:u1', 'agent:'.$current->id])->checkDelegated(
        new SubjectRef('user', 'u1'),
        $chain,
        ['permission' => 'orders.read'],
    );

    expect($decision['allowed'])->toBeFalse();

    // Controprova: con la radice autorizzata, la stessa catena passa.
    expect(engineWith(['user:u1', 'agent:'.$root->id, 'agent:'.$current->id])
        ->checkDelegated(new SubjectRef('user', 'u1'), $chain, ['permission' => 'orders.read'])['allowed'])
        ->toBeTrue();
});

it('cita un sub_decision per OGNI hop, cosi\' l\'auditor puo\' rigiocarli separatamente', function () {
    $a = activeAgentRow();
    $b = activeAgentRow();

    $decision = engineWith(['user:u1', 'agent:'.$a->id, 'agent:'.$b->id])->checkDelegated(
        new SubjectRef('user', 'u1'),
        // $a e' l'attore CORRENTE (actors[0], il piu' esterno nel claim `act`).
        new DelegationChain(ActorRef::fromAgentId($a->id), ActorRef::fromAgentId($b->id)),
        ['permission' => 'orders.read'],
    );

    expect($decision['actors'])->toBe(['agent:'.$a->id, 'agent:'.$b->id])
        ->and($decision['sub_decisions']['actors'])->toHaveCount(2)
        ->and($decision['sub_decisions']['actors'])->toHaveKeys(['agent:'.$a->id, 'agent:'.$b->id])
        // `actor` resta l'attore CORRENTE: i consumer scritti per il single-hop,
        // che leggevano una catena da un anello solo, non si rompono.
        ->and($decision['sub_decisions']['actor'])
        ->toBe($decision['sub_decisions']['actors']['agent:'.$a->id]);
});

it('un hop sospeso a meta\' catena ferma tutta la catena', function () {
    $a = activeAgentRow();
    $b = activeAgentRow();
    $a->fill(['status' => AgentStatus::Suspended->value])->save();

    $decision = engineWith(['user:u1', 'agent:'.$a->id, 'agent:'.$b->id])->checkDelegated(
        new SubjectRef('user', 'u1'),
        new DelegationChain(ActorRef::fromAgentId($a->id), ActorRef::fromAgentId($b->id)),
        ['permission' => 'orders.read'],
    );

    expect($decision['allowed'])->toBeFalse()->and($decision['reason'])->toBe('agent_not_active');
});

it('requires_step_up si propaga da QUALSIASI hop, non solo dall\'ultimo', function () {
    $a = activeAgentRow();
    $b = activeAgentRow();

    // Engine che chiede step-up solo per A (l'hop intermedio).
    $engine = new DelegatedEngine(
        new class($a->id) implements AuthorizationEngine
        {
            public function __construct(private readonly string $stepUpFor) {}

            public function check(array $query): array
            {
                $id = $query['subject']['id'] ?? '';

                return [
                    'allowed' => true,
                    'decision_id' => 'dec_'.substr(md5((string) $id), 0, 8),
                    'policy_version' => 7,
                    'requires_step_up' => $id === $this->stepUpFor,
                ];
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
    );

    $decision = $engine->checkDelegated(
        new SubjectRef('user', 'u1'),
        new DelegationChain(ActorRef::fromAgentId($a->id), ActorRef::fromAgentId($b->id)),
        ['permission' => 'orders.read'],
    );

    expect($decision['requires_step_up'])->toBeTrue();
});
