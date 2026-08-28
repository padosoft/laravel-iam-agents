<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Agents\Http\Controllers\SelfServiceDelegationsController;
use Padosoft\Iam\Agents\Consent\ConsentPreview;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Contracts\Delegation\AgentRegistry;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Support\SubjectRef;

uses(RefreshDatabase::class);

/**
 * Engine finto: reverse-index deterministico per soggetto+relazione.
 *
 * @param  array<string, list<string>>  $reach  "type:id|relation" => risorse
 */
function previewEngine(array $reach): AuthorizationEngine
{
    return new class($reach) implements AuthorizationEngine
    {
        public function __construct(private readonly array $reach) {}

        public function check(array $query): array
        {
            return ['allowed' => false, 'decision_id' => 'dec_x', 'policy_version' => 1];
        }

        public function listSubjects(string $relation, string $objectType, string $objectId): iterable
        {
            return [];
        }

        public function listResources(SubjectRef $subject, string $relation): iterable
        {
            return $this->reach[((string) $subject).'|'.$relation] ?? [];
        }
    };
}

function previewAgent(AgentStatus $status = AgentStatus::Active): Agent
{
    return Agent::query()->create([
        'id' => Agent::newId(),
        'name' => 'Preview Agent',
        'max_scopes' => ['orders:read'],
        'status' => $status->value,
    ]);
}

function previewFor(array $reach, int $limit = 25): ConsentPreview
{
    return new ConsentPreview(previewEngine($reach), app(AgentRegistry::class), $limit);
}

it('mostra l\'INTERSEZIONE, non l\'unione: le risorse che entrambi raggiungono', function () {
    $agent = previewAgent();
    $user = new SubjectRef('user', 'u1');

    // L'utente arriva a 1,2,3; l'agente a 2,3,4. Solo 2 e 3 sono davvero delegabili.
    $preview = previewFor([
        'user:u1|owner' => ['order:1', 'order:2', 'order:3'],
        'agent:'.$agent->id.'|owner' => ['order:2', 'order:3', 'order:4'],
    ])->forGrant($user, $agent->subject(), ['owner']);

    expect($preview['agent_status'])->toBe('active')
        ->and($preview['relations'][0]['resources'])->toBe(['order:2', 'order:3'])
        ->and($preview['relations'][0]['total'])->toBe(2)
        ->and($preview['relations'][0]['truncated'])->toBeFalse();
});

it('dichiara il troncamento invece di far sembrare piccola una delega grande', function () {
    $agent = previewAgent();
    $many = array_map(static fn (int $i): string => 'order:'.str_pad((string) $i, 4, '0', STR_PAD_LEFT), range(1, 100));

    $preview = previewFor([
        'user:u1|owner' => $many,
        'agent:'.$agent->id.'|owner' => $many,
    ], limit: 10)->forGrant(new SubjectRef('user', 'u1'), $agent->subject(), ['owner']);

    $relation = $preview['relations'][0];

    // Dieci mostrate, ma il totale reale e' dichiarato: l'utente sa che sono 100.
    expect($relation['resources'])->toHaveCount(10)
        ->and($relation['total'])->toBe(100)
        ->and($relation['truncated'])->toBeTrue();
});

it('un agente non attivo non mostra risorse: non le riceverebbe comunque', function () {
    $agent = previewAgent(AgentStatus::Suspended);

    $preview = previewFor([
        'user:u1|owner' => ['order:1'],
        'agent:'.$agent->id.'|owner' => ['order:1'],
    ])->forGrant(new SubjectRef('user', 'u1'), $agent->subject(), ['owner']);

    expect($preview['agent_status'])->toBe('suspended')->and($preview['relations'])->toBe([]);
});

it('nessuna sovrapposizione ⇒ lista vuota, che e\' l\'informazione utile', function () {
    $agent = previewAgent();

    $preview = previewFor([
        'user:u1|owner' => ['order:1'],
        'agent:'.$agent->id.'|owner' => ['order:9'],
    ])->forGrant(new SubjectRef('user', 'u1'), $agent->subject(), ['owner']);

    // Concedere questa delega non darebbe accesso a NULLA: va detto prima, non dopo.
    expect($preview['relations'][0]['total'])->toBe(0)
        ->and($preview['relations'][0]['resources'])->toBe([]);
});

it('relations vuote ⇒ 422, non un preview vuoto', function () {
    // Un preview senza relazioni sarebbe indistinguibile da "non hai accesso a
    // nulla": due significati opposti che non devono produrre la stessa risposta.
    // Qui si esercita il ramo di validazione del controller, non la rotta HTTP:
    // in questo pacchetto le superfici self-service non hanno un harness HTTP.
    $controller = app(SelfServiceDelegationsController::class);
    $preview = previewFor([]);

    $missingRelations = $controller->consentPreview(
        Request::create('/', 'POST', ['agent_id' => 'agt_x', 'relations' => []]),
        $preview,
    );
    $missingAgent = $controller->consentPreview(
        Request::create('/', 'POST', ['relations' => ['owner']]),
        $preview,
    );

    expect($missingRelations->getStatusCode())->toBe(422)
        ->and($missingAgent->getStatusCode())->toBe(422);
});
