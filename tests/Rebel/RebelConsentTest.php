<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Agents\Consent\ConsentFailedException;
use Padosoft\Iam\Agents\Consent\ConsentPayload;
use Padosoft\Iam\Agents\Consent\ConsentVerifier;
use Padosoft\Iam\Agents\Consent\RebelStepUpConsentVerifier;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Rebel\Core\Assurance\Aal;
use Padosoft\Rebel\Core\Assurance\AssuranceLevel;
use Padosoft\Rebel\StepUp\DriverRegistry;
use Padosoft\Rebel\StepUp\Testing\FakeStepUpDriver;

uses(RefreshDatabase::class);

/**
 * Mondo di test: driver fake registrato + purpose `iam-delegation-grant` con
 * dynamic linking SCA attivo (il binding di agent/scopes/ttl/purpose è enforcement
 * rebel-side, non emulazione). Il FakeStepUpDriver accetta il codice '123456'.
 */
function rebelConsentWorld(Aal $driverAal = Aal::Aal2, string $requiredAssurance = 'aal2'): array
{
    app(DriverRegistry::class)->register(
        new FakeStepUpDriver('fake', new AssuranceLevel($driverAal, true, ['fake'])),
    );
    config()->set('rebel-step-up.purposes.iam-delegation-grant', [
        'required_assurance' => $requiredAssurance,
        'drivers' => ['fake'],
        'always_require' => true,
        'sca' => ['dynamic_linking' => true],
    ]);

    return [
        'verifier' => app(RebelStepUpConsentVerifier::class),
        'subject' => new SubjectRef('user', '42'),
        'payload' => new ConsentPayload('agt_x', ['orders:read'], 3600, 'Assistenza ordini'),
    ];
}

it('challenge → confirm → evidenza AAL2 riferita alla challenge confermata', function () {
    $w = rebelConsentWorld();

    $challenge = $w['verifier']->challenge($w['subject'], $w['payload'], null);
    expect($challenge['challenge_id'])->not->toBe('')
        ->and($challenge['method'])->toBe('fake')
        ->and($challenge['expires_at'])->not->toBe('');

    $evidence = $w['verifier']->verifyAndConsume($w['subject'], $w['payload'], $challenge['challenge_id'], ['code' => '123456']);
    expect($evidence->confirmationId)->toBe($challenge['challenge_id'])
        ->and($evidence->aal->value)->toBe('aal2');
});

it('parametri cambiati dopo la schermata ⇒ binding mismatch rebel-side (dynamic linking VERO)', function () {
    $w = rebelConsentWorld();
    $challenge = $w['verifier']->challenge($w['subject'], $w['payload'], null);

    // Stesso agente ma scope allargati: l'hash canonico keyed diverge ⇒ rebel rifiuta.
    $tampered = new ConsentPayload('agt_x', ['orders:read', 'orders:write'], 3600, 'Assistenza ordini');

    expect(fn () => $w['verifier']->verifyAndConsume($w['subject'], $tampered, $challenge['challenge_id'], ['code' => '123456']))
        ->toThrow(ConsentFailedException::class);
});

it('codice errato ⇒ ConsentFailedException con la reason del driver', function () {
    $w = rebelConsentWorld();
    $challenge = $w['verifier']->challenge($w['subject'], $w['payload'], null);

    expect(fn () => $w['verifier']->verifyAndConsume($w['subject'], $w['payload'], $challenge['challenge_id'], ['code' => '000000']))
        ->toThrow(ConsentFailedException::class, 'wrong_input');
});

it('codice mancante o challenge_id vuota ⇒ rifiuto immediato', function () {
    $w = rebelConsentWorld();

    expect(fn () => $w['verifier']->verifyAndConsume($w['subject'], $w['payload'], '', ['code' => '123456']))
        ->toThrow(ConsentFailedException::class)
        ->and(fn () => $w['verifier']->verifyAndConsume($w['subject'], $w['payload'], 'ch_x', []))
        ->toThrow(ConsentFailedException::class);
});

it('AAL raggiunto sotto il minimo del modulo ⇒ fail-closed anche se rebel conferma', function () {
    // Purpose rebel ad aal1 con driver aal1: la conferma rebel RIESCE, ma il modulo
    // richiede aal2 (iam-agents.consent.required_aal) ⇒ l\'evidenza va rifiutata QUI.
    $w = rebelConsentWorld(driverAal: Aal::Aal1, requiredAssurance: 'aal1');
    $challenge = $w['verifier']->challenge($w['subject'], $w['payload'], null);

    expect(fn () => $w['verifier']->verifyAndConsume($w['subject'], $w['payload'], $challenge['challenge_id'], ['code' => '123456']))
        ->toThrow(ConsentFailedException::class, 'insufficiente');
});

it('utenti diversi non condividono la challenge (subject nel contesto rebel)', function () {
    $w = rebelConsentWorld();
    $challenge = $w['verifier']->challenge($w['subject'], $w['payload'], null);

    expect(fn () => $w['verifier']->verifyAndConsume(new SubjectRef('user', 'intruso'), $w['payload'], $challenge['challenge_id'], ['code' => '123456']))
        ->toThrow(ConsentFailedException::class);
});

it('il container risolve l\'adapter dal config FQCN (attivazione via iam-agents.consent.verifier)', function () {
    rebelConsentWorld();
    config()->set('iam-agents.consent.verifier', RebelStepUpConsentVerifier::class);

    expect(app(ConsentVerifier::class))->toBeInstanceOf(RebelStepUpConsentVerifier::class);
});
