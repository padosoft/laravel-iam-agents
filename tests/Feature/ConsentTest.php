<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Agents\Consent\ConsentFailedException;
use Padosoft\Iam\Agents\Consent\ConsentPayload;
use Padosoft\Iam\Agents\Consent\IamNativeConsentVerifier;
use Padosoft\Iam\Agents\Consent\NullConsentVerifier;
use Padosoft\Iam\Contracts\Assurance\FactorVerifier;
use Padosoft\Iam\Contracts\Identity\SessionMeta;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Identity\Models\User;

uses(RefreshDatabase::class);

function consentWorld(): array
{
    // Fattore sempre-valido nei test: il default del server (Unconfigured) è fail-closed.
    app()->bind(FactorVerifier::class, fn () => new class implements FactorVerifier
    {
        public function verify(SubjectRef $subject, array $payload): bool
        {
            return ($payload['code'] ?? null) === '123456';
        }
    });

    $user = User::query()->create(['email' => 'consent@test.it']);
    $subject = new SubjectRef('user', (string) $user->id);
    $session = app(SessionRegistry::class)->start($subject, new SessionMeta);

    return [
        'verifier' => app(IamNativeConsentVerifier::class),
        'subject' => $subject,
        'session' => $session,
        'payload' => new ConsentPayload('agt_x', ['orders:read'], 3600, 'Assistenza ordini'),
    ];
}

it('challenge → verifica → evidenza (AAL2), con binding dei parametri', function () {
    $w = consentWorld();

    $challenge = $w['verifier']->challenge($w['subject'], $w['payload'], $w['session']);
    expect($challenge['challenge_id'])->not->toBe('');

    $evidence = $w['verifier']->verifyAndConsume($w['subject'], $w['payload'], $challenge['challenge_id'], ['code' => '123456']);
    expect($evidence->confirmationId)->toBe($challenge['challenge_id'])
        ->and($evidence->aal->value)->toBe('aal2');
});

it('parametri cambiati dopo la schermata ⇒ binding mismatch (dynamic-linking)', function () {
    $w = consentWorld();
    $challenge = $w['verifier']->challenge($w['subject'], $w['payload'], $w['session']);

    // Stesso agente ma scope allargati: l'hash canonico diverge ⇒ rifiuto netto.
    $tampered = new ConsentPayload('agt_x', ['orders:read', 'orders:write'], 3600, 'Assistenza ordini');

    expect(fn () => $w['verifier']->verifyAndConsume($w['subject'], $tampered, $challenge['challenge_id'], ['code' => '123456']))
        ->toThrow(ConsentFailedException::class);
});

it('la conferma è one-shot: la stessa challenge non si consuma due volte', function () {
    $w = consentWorld();
    $challenge = $w['verifier']->challenge($w['subject'], $w['payload'], $w['session']);

    $w['verifier']->verifyAndConsume($w['subject'], $w['payload'], $challenge['challenge_id'], ['code' => '123456']);

    expect(fn () => $w['verifier']->verifyAndConsume($w['subject'], $w['payload'], $challenge['challenge_id'], ['code' => '123456']))
        ->toThrow(ConsentFailedException::class);
});

it('codice errato ⇒ rifiuto SENZA bruciare la challenge (retry possibile)', function () {
    $w = consentWorld();
    $challenge = $w['verifier']->challenge($w['subject'], $w['payload'], $w['session']);

    expect(fn () => $w['verifier']->verifyAndConsume($w['subject'], $w['payload'], $challenge['challenge_id'], ['code' => '000000']))
        ->toThrow(ConsentFailedException::class);

    // Retry col codice giusto: la challenge è ancora viva.
    $evidence = $w['verifier']->verifyAndConsume($w['subject'], $w['payload'], $challenge['challenge_id'], ['code' => '123456']);
    expect($evidence->confirmationId)->toBe($challenge['challenge_id']);
});

it('utente diverso da chi ha aperto la challenge ⇒ rifiuto', function () {
    $w = consentWorld();
    $challenge = $w['verifier']->challenge($w['subject'], $w['payload'], $w['session']);

    expect(fn () => $w['verifier']->verifyAndConsume(new SubjectRef('user', 'intruso'), $w['payload'], $challenge['challenge_id'], ['code' => '123456']))
        ->toThrow(ConsentFailedException::class);
});

it('senza sessione IAM il consenso nativo rifiuta (fail-closed)', function () {
    $w = consentWorld();

    expect(fn () => $w['verifier']->challenge($w['subject'], $w['payload'], null))
        ->toThrow(ConsentFailedException::class);
});

it('il default NullConsentVerifier rifiuta tutto (modulo non configurato = zero deleghe)', function () {
    $w = consentWorld();
    $null = new NullConsentVerifier;

    expect(fn () => $null->challenge($w['subject'], $w['payload'], $w['session']))
        ->toThrow(ConsentFailedException::class)
        ->and(fn () => $null->verifyAndConsume($w['subject'], $w['payload'], 'x', []))
        ->toThrow(ConsentFailedException::class);
});

it('una delega senza scope non è nemmeno esprimibile', function () {
    expect(fn () => new ConsentPayload('agt_x', [], 3600, 'p'))
        ->toThrow(InvalidArgumentException::class);
});
