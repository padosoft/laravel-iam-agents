<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Consent;

use Padosoft\Iam\Contracts\Identity\SessionRef;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * La porta del consenso di delega. Due implementazioni nel modulo:
 * - IamNativeConsentVerifier: step-up nativo IAM (claim single-use reale) + binding
 *   dei parametri emulato module-side (hash canonico in cache alla challenge).
 * - NullConsentVerifier (default): rifiuta tutto — il modulo non configurato non
 *   concede nulla.
 * Un adapter rebel-step-up (dynamic linking PSD2-grade) arriva col patch P5 upstream.
 */
interface ConsentVerifier
{
    /**
     * Apre la challenge di consenso per i parametri dati (che vengono VINCOLATI alla
     * challenge: cambiarli dopo invalida la conferma).
     *
     * @return array{challenge_id: string, method: string, expires_at: string}
     */
    public function challenge(SubjectRef $user, ConsentPayload $payload, ?SessionRef $session): array;

    /**
     * Verifica la risposta dell'utente alla challenge E la consuma (one-shot),
     * ri-controllando che i parametri presentati alla creazione della grant siano
     * ESATTAMENTE quelli vincolati alla challenge.
     *
     * @param  array<string, mixed>  $verification  es. ['code' => '123456']
     *
     * @throws ConsentFailedException su qualunque mismatch (fail-closed)
     */
    public function verifyAndConsume(
        SubjectRef $user,
        ConsentPayload $payload,
        string $challengeId,
        array $verification,
    ): ConsentEvidence;
}
