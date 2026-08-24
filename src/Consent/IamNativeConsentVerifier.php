<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Consent;

use Illuminate\Contracts\Cache\Repository as Cache;
use Padosoft\Iam\Contracts\Assurance\Aal;
use Padosoft\Iam\Contracts\Assurance\StepUpProvider;
use Padosoft\Iam\Contracts\Assurance\StepUpPurpose;
use Padosoft\Iam\Contracts\Identity\SessionRef;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Consenso via step-up NATIVO IAM (NativeStepUpProvider: claim single-use atomico,
 * cap AAL2). Il binding dei parametri — l'analogo del dynamic linking PSD2 — è
 * emulato module-side: alla challenge l'hash canonico di (agent, scopes, ttl,
 * purpose) viene fissato in cache; alla verifica i parametri presentati DEVONO
 * riprodurre lo stesso hash, o il consenso è rifiutato. Parametri cambiati dopo
 * la schermata ⇒ conferma invalida.
 */
final class IamNativeConsentVerifier implements ConsentVerifier
{
    private const CACHE_PREFIX = 'iam-agents:consent:';

    /** TTL del binding in cache: allineato alla finestra della challenge nativa. */
    private const BINDING_TTL = 600;

    public function __construct(
        private readonly StepUpProvider $stepUp,
        private readonly Cache $cache,
    ) {}

    public function challenge(SubjectRef $user, ConsentPayload $payload, ?SessionRef $session): array
    {
        if ($session === null) {
            throw new ConsentFailedException('Il consenso nativo richiede una sessione IAM attiva (SessionRef).');
        }

        $purpose = new StepUpPurpose(
            action: $this->purposeAction(),
            requiredAal: $this->requiredAal(),
        );

        $challenge = $this->stepUp->require($user, $purpose, $session);

        // Dynamic-linking module-side: vincola la challenge ai parametri del consenso.
        $this->cache->put(self::CACHE_PREFIX.$challenge->id, [
            'user' => (string) $user,
            'binding' => $payload->bindingHash(),
        ], self::BINDING_TTL);

        return [
            'challenge_id' => $challenge->id,
            'method' => $challenge->method,
            'expires_at' => $challenge->expiresAt->format(\DateTimeInterface::ATOM),
        ];
    }

    public function verifyAndConsume(SubjectRef $user, ConsentPayload $payload, string $challengeId, array $verification): ConsentEvidence
    {
        if ($challengeId === '') {
            throw new ConsentFailedException('challenge_id mancante.');
        }

        // 1) Binding PRIMA del fattore: parametri divergenti ⇒ niente consumo della
        //    challenge (l'utente può ripresentare quelli giusti), ma rifiuto netto.
        $bound = $this->cache->get(self::CACHE_PREFIX.$challengeId);
        if (!is_array($bound)
            || ($bound['user'] ?? null) !== (string) $user
            || !is_string($bound['binding'] ?? null)
            || !hash_equals($bound['binding'], $payload->bindingHash())
        ) {
            throw new ConsentFailedException('Binding del consenso non valido: parametri diversi da quelli confermati.');
        }

        // 2) Verifica del fattore + claim single-use atomico (NativeStepUpProvider).
        $result = $this->stepUp->verify($challengeId, $verification);
        if (!$result->success) {
            throw new ConsentFailedException('Verifica step-up del consenso fallita.');
        }

        // 3) AAL raggiunto DEVE soddisfare il minimo richiesto (esplicito, mai implicito).
        if (!$result->aal->satisfies($this->requiredAal())) {
            throw new ConsentFailedException("AAL del consenso insufficiente ({$result->aal->value} < {$this->requiredAal()->value}).");
        }

        // 4) Il binding è bruciato insieme alla challenge (one-shot anche lato cache).
        $this->cache->forget(self::CACHE_PREFIX.$challengeId);

        return new ConsentEvidence(confirmationId: $challengeId, aal: $result->aal);
    }

    private function purposeAction(): string
    {
        $purpose = config('iam-agents.consent.purpose', 'iam-delegation-grant');

        return is_string($purpose) && $purpose !== '' ? $purpose : 'iam-delegation-grant';
    }

    private function requiredAal(): Aal
    {
        // NB: NON Aal::fromString — quella degrada l'ignoto ad AAL1 (fail-safe per i livelli
        // CORRENTI, fail-open per i REQUISITI). Un typo in config non deve abbassare il
        // requisito del consenso: sconosciuto ⇒ AAL2 (stessa lezione di rebel-step-up).
        $aal = config('iam-agents.consent.required_aal', 'aal2');
        $parsed = is_string($aal) ? Aal::tryFrom($aal) : null;

        return $parsed ?? Aal::AAL2;
    }
}
