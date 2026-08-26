<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Agents\Freeze\DelegationFreezeService;
use Padosoft\Iam\Agents\Freeze\FreezeScope;
use Padosoft\Iam\Agents\Http\Controllers\AgentReceiptsController;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Agents\Models\DelegationReceiptModel;
use Padosoft\Iam\Agents\Receipts\ActionReceipt;
use Padosoft\Iam\Agents\Receipts\DelegationReceiptService;
use Padosoft\Iam\Agents\Receipts\ReceiptException;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Contracts\Delegation\ActClaim;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStore;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;

uses(RefreshDatabase::class);

/**
 * Ricevute d'azione delegata.
 *
 * Ciò che questi test pinnano non è "il JWS si firma" — è **chi** può firmarlo e
 * **quando**: solo chi ha il token delegato, solo mentre la grant è viva, mai da
 * un token utente pieno, mai a delega congelata. Senza quei confini una ricevuta
 * non sarebbe evidenza, sarebbe carta.
 *
 * @return array{agent: Agent, grant: DelegationGrantModel, token: string, user: SubjectRef}
 */
function receiptWorld(): array
{
    $agent = Agent::query()->create([
        'id' => Agent::newId(),
        'name' => 'CRM Agent',
        'max_scopes' => ['orders:read', 'orders:write'],
        'status' => AgentStatus::Active->value,
    ]);

    $user = new SubjectRef('user', 'u1');

    $grant = DelegationGrantModel::query()->create([
        'id' => DelegationGrantModel::newId(),
        'user_type' => $user->type, 'user_id' => $user->id,
        'agent_id' => $agent->id,
        'scopes' => ['orders:read'],
        'purpose' => 'Assistenza ordini',
        'status' => DelegationGrantStatus::Active->value,
        'expires_at' => now()->addDay(),
    ]);

    return [
        'agent' => $agent,
        'grant' => $grant,
        'token' => delegatedTokenFor($user->id, $agent->id, $grant->id),
        'user' => $user,
    ];
}

function delegatedTokenFor(string $userId, string $agentId, string $grantId): string
{
    return app(TokenSigner::class)->issue([
        'sub' => $userId,
        ActClaim::ACT => ['sub' => 'agent:'.$agentId],
        ActClaim::CLAIM_DELEGATION_GRANT => $grantId,
        'scope' => 'orders:read',
    ], 300);
}

function receipts(): DelegationReceiptService
{
    return app(DelegationReceiptService::class);
}

it('conia una ricevuta e ne prende le identità DAL TOKEN, non dal body', function () {
    $w = receiptWorld();

    $model = receipts()->mint($w['token'], [
        'action' => 'orders.create',
        'resource' => 'order:9001',
        'outcome' => ActionReceipt::OUTCOME_OK,
        'decision_id' => 'dec_abc',
    ]);

    expect($model->subject_id)->toBe('u1')
        ->and($model->agent_id)->toBe($w['agent']->id)
        ->and($model->grant_id)->toBe($w['grant']->id)
        ->and($model->action)->toBe('orders.create')
        ->and($model->payload_digest)->toStartWith('sha256:');

    $verified = receipts()->verify($model->jws);

    expect((string) $verified->subject)->toBe('user:u1')
        ->and((string) $verified->agent)->toBe('agent:'.$w['agent']->id)
        ->and($verified->grantId)->toBe($w['grant']->id)
        ->and($verified->action)->toBe('orders.create')
        ->and($verified->resource)->toBe('order:9001')
        ->and($verified->outcome)->toBe(ActionReceipt::OUTCOME_OK)
        ->and($verified->decisionId)->toBe('dec_abc');
});

it('un token UTENTE pieno non conia: firmerebbe l\'utente come se fosse un agente', function () {
    $w = receiptWorld();
    $plain = app(TokenSigner::class)->issue(['sub' => 'u1', 'scope' => 'orders:read'], 300);

    expect(fn () => receipts()->mint($plain, ['action' => 'orders.create']))
        ->toThrow(ReceiptException::class);
});

it('nessun token, o un token non firmato da noi, non conia', function () {
    receiptWorld();

    expect(fn () => receipts()->mint('', ['action' => 'x']))->toThrow(ReceiptException::class)
        ->and(fn () => receipts()->mint('not.a.jwt', ['action' => 'x']))->toThrow(ReceiptException::class);
});

it('una grant revocata non conia più: niente storia retrodatata', function () {
    // È il momento in cui un agente appena tagliato fuori avrebbe più interesse a
    // firmare azioni mai avvenute.
    $w = receiptWorld();
    app(DelegationGrantStore::class)->revoke($w['grant']->id, new SubjectRef('user', 'admin'));

    expect(fn () => receipts()->mint($w['token'], ['action' => 'orders.create']))
        ->toThrow(ReceiptException::class);
});

it('un agente sospeso non conia', function () {
    $w = receiptWorld();
    $w['agent']->fill(['status' => AgentStatus::Suspended->value])->save();

    expect(fn () => receipts()->mint($w['token'], ['action' => 'orders.create']))
        ->toThrow(ReceiptException::class);
});

it('a delega congelata non si firma: firmare è un\'azione', function () {
    $w = receiptWorld();
    app(DelegationFreezeService::class)->freeze(FreezeScope::Global, null, 'Incidente', new SubjectRef('user', 'alice'));

    expect(fn () => receipts()->mint($w['token'], ['action' => 'orders.create']))
        ->toThrow(ReceiptException::class);
});

it('un token che cita una grant di un\'ALTRA coppia utente/agente non conia', function () {
    $w = receiptWorld();
    $other = Agent::query()->create([
        'id' => Agent::newId(), 'name' => 'Other', 'max_scopes' => [], 'status' => AgentStatus::Active->value,
    ]);

    // Token dell'altro agente che punta alla grant del primo.
    $forged = delegatedTokenFor('u1', $other->id, $w['grant']->id);

    expect(fn () => receipts()->mint($forged, ['action' => 'orders.create']))
        ->toThrow(ReceiptException::class);
});

it('azione mancante o esito non riconosciuto sono rifiutati', function () {
    $w = receiptWorld();

    expect(fn () => receipts()->mint($w['token'], ['action' => '  ']))->toThrow(ReceiptException::class)
        ->and(fn () => receipts()->mint($w['token'], ['action' => 'x', 'outcome' => 'maybe']))->toThrow(ReceiptException::class);
});

it('la stessa idempotency key restituisce la stessa ricevuta, non una seconda', function () {
    // Le reti mobili ritentano: due POST identici non devono raccontare due azioni.
    $w = receiptWorld();

    $first = receipts()->mint($w['token'], ['action' => 'orders.create', 'idempotency_key' => 'k1']);
    $second = receipts()->mint($w['token'], ['action' => 'orders.create', 'idempotency_key' => 'k1']);

    expect($second->id)->toBe($first->id)
        ->and(DelegationReceiptModel::query()->count())->toBe(1);
});

it('una ricevuta non è un access token: la aud dedicata la esclude', function () {
    // Stesso issuer, stessa forma, sub = utente. Senza aud dedicata un resource
    // server distratto potrebbe accettarla come autorità.
    $w = receiptWorld();
    $model = receipts()->mint($w['token'], ['action' => 'orders.create']);

    $claims = app(TokenSigner::class)->parse($model->jws);

    expect((array) $claims['aud'])->toContain(ActionReceipt::AUDIENCE)
        ->and($claims['pds_att'])->toBe('actor')
        ->and($claims)->not->toHaveKey('scope');
});

it('verify rifiuta un access token delegato spacciato per ricevuta', function () {
    $w = receiptWorld();

    expect(fn () => receipts()->verify($w['token']))->toThrow(ReceiptException::class);
});

it('emissione e rifiuto finiscono entrambi nello stream delegation', function () {
    $w = receiptWorld();
    receipts()->mint($w['token'], ['action' => 'orders.create']);

    $controller = app(AgentReceiptsController::class);
    $refused = $controller->store(Request::create('/', 'POST', ['action' => 'orders.create']));

    expect($refused->getStatusCode())->toBe(422);

    $types = AuditEvent::query()->where('stream', 'delegation')->pluck('event_type')->all();

    expect($types)->toContain('iam.delegation.receipt.issued')
        ->and($types)->toContain('iam.delegation.receipt.refused');
});

it('il rifiuto al client è generico: il motivo resta nell\'audit', function () {
    // Dire a un agente PERCHÉ non ha potuto firmare gli insegna come provarci meglio.
    receiptWorld();

    $response = app(AgentReceiptsController::class)->store(Request::create('/', 'POST', ['action' => 'x']));

    /** @var array<string, mixed> $body */
    $body = json_decode((string) $response->getContent(), true);

    expect($body)->toBe(['error' => 'receipt_not_issued']);
});

it('il controller conia dal Bearer e restituisce il JWS all\'agente che lo ha firmato', function () {
    $w = receiptWorld();

    $request = Request::create('/', 'POST', ['action' => 'orders.create', 'resource' => 'order:1']);
    $request->headers->set('Authorization', 'Bearer '.$w['token']);

    $response = app(AgentReceiptsController::class)->store($request);
    /** @var array<string, mixed> $body */
    $body = json_decode((string) $response->getContent(), true);

    expect($response->getStatusCode())->toBe(201)
        ->and($body['data']['id'])->toStartWith('rcp_')
        ->and(receipts()->verify($body['data']['receipt'])->action)->toBe('orders.create');
});
