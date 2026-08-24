<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Agents\Consent\ConsentFailedException;
use Padosoft\Iam\Agents\Consent\ConsentPayload;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Contracts\Delegation\BudgetVerdict;
use Padosoft\Iam\Contracts\Delegation\DelegationBudget;
use Padosoft\Iam\Contracts\Delegation\DelegationBudgetGuard;
use Padosoft\Iam\Contracts\Delegation\DelegationGrant;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;

uses(RefreshDatabase::class);

// ── ConsentPayload: il budget entra nel binding, la firma resta posizional-BC ──

it('ConsentPayload: arity posizionale pre-budget ancora costruibile (lezione flow v2.2.1)', function () {
    $payload = new ConsentPayload('agt_x', ['orders:read'], 3600, 'p'); // 4 posizionali storici
    expect($payload->budget)->toBeNull();
});

it('il budget cambia il binding hash: intensità approvata insieme all\'autorità', function () {
    $plain = new ConsentPayload('agt_x', ['orders:read'], 3600, 'p');
    $budgeted = new ConsentPayload('agt_x', ['orders:read'], 3600, 'p', new DelegationBudget(amount: 25.0));
    $other = new ConsentPayload('agt_x', ['orders:read'], 3600, 'p', new DelegationBudget(amount: 50.0));

    expect($plain->bindingHash())->not->toBe($budgeted->bindingHash())
        ->and($budgeted->bindingHash())->not->toBe($other->bindingHash());
});

it('un DelegationBudget senza cap o con cap non positivi non è esprimibile', function () {
    expect(fn () => new DelegationBudget)->toThrow(InvalidArgumentException::class)
        ->and(fn () => new DelegationBudget(amount: -1.0))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new DelegationBudget(tokens: 0))->toThrow(InvalidArgumentException::class);
});

// ── Exchange: fail-closed su budget non enforceable / esaurito ──

function budgetedExchangeWorld(?DelegationBudget $budget): array
{
    $world = seedExchangeWorld();
    DelegationGrantModel::query()->whereKey($world['grant']->id)
        ->update(['budget' => $budget !== null ? json_encode($budget->toArray()) : null]);

    return $world;
}

it('grant CON budget e NESSUN meter bindato ⇒ exchange rifiutato (budget_unenforceable)', function () {
    $world = budgetedExchangeWorld(new DelegationBudget(amount: 25.0));

    exchangeRequest($world['subjectToken'])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

    $refused = AuditEvent::query()->where('event_type', 'iam.delegation.exchange.refused')->latest('id')->first();
    expect($refused->metadata_json['refusal_reason'] ?? null)->toBe('delegation_budget_unenforceable');
});

it('meter che NEGA ⇒ exchange rifiutato con la reason auditata; che PERMETTE ⇒ token emesso', function () {
    $world = budgetedExchangeWorld(new DelegationBudget(calls: 10));

    app()->instance(DelegationBudgetGuard::class, new class implements DelegationBudgetGuard
    {
        public bool $allow = false;

        public function verdict(DelegationGrant $grant): BudgetVerdict
        {
            return $this->allow ? BudgetVerdict::allow(['calls' => 3]) : BudgetVerdict::deny('calls 10/10');
        }
    });

    exchangeRequest($world['subjectToken'])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    $refused = AuditEvent::query()->where('event_type', 'iam.delegation.exchange.refused')->latest('id')->first();
    expect($refused->metadata_json['refusal_reason'] ?? null)->toBe('delegation_budget_exhausted: calls 10/10');

    app(DelegationBudgetGuard::class)->allow = true;
    exchangeRequest($world['subjectToken'])->assertOk();
});

it('grant SENZA budget non interroga mai il meter (nessun guard richiesto)', function () {
    $world = budgetedExchangeWorld(null);

    exchangeRequest($world['subjectToken'])->assertOk(); // nessun binding del guard nel container
});

// ── Self-service: il budget fa parte del consenso (dynamic linking) ──

it('consenso con budget: la grant lo persiste; budget cambiato dopo la challenge ⇒ rifiuto', function () {
    $w = consentWorld();
    $budget = ['amount' => 25.5, 'currency' => 'EUR', 'calls' => 100];
    $payloadWithBudget = new ConsentPayload('agt_x', ['orders:read'], 3600, 'Assistenza ordini', DelegationBudget::fromArray($budget));

    $challenge = $w['verifier']->challenge($w['subject'], $payloadWithBudget, $w['session']);

    // Stessi parametri MA budget diverso: binding mismatch ⇒ rifiuto netto.
    $tampered = new ConsentPayload('agt_x', ['orders:read'], 3600, 'Assistenza ordini', new DelegationBudget(amount: 999.0));
    expect(fn () => $w['verifier']->verifyAndConsume($w['subject'], $tampered, $challenge['challenge_id'], ['code' => '123456']))
        ->toThrow(ConsentFailedException::class);

    // Con il budget ESATTO consentito la conferma passa.
    $evidence = $w['verifier']->verifyAndConsume($w['subject'], $payloadWithBudget, $challenge['challenge_id'], ['code' => '123456']);
    expect($evidence->aal->value)->toBe('aal2');
});
