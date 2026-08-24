<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Consent;

use Illuminate\Auth\GenericUser;
use Illuminate\Support\Str;
use Padosoft\Iam\Contracts\Assurance\Aal;
use Padosoft\Iam\Contracts\Identity\SessionRef;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Rebel\Core\Context\SecurityContext;
use Padosoft\Rebel\StepUp\Models\StepUpChallenge;
use Padosoft\Rebel\StepUp\RebelStepUp;
use Padosoft\Rebel\StepUp\Sca\GenericBindingContext;
use Padosoft\Rebel\StepUp\StepUpContext;

/**
 * Consenso via rebel-step-up (>= 0.2): il dynamic linking PSD2-grade VERO. Il binding
 * di (agent, scopes, ttl, purpose) non è emulato in cache come nel verifier nativo:
 * è la GenericBindingContext di rebel (P5) — l'hash canonico keyed vive sulla
 * challenge, e confirm() lo ri-verifica driver-side. Parametri cambiati dopo la
 * schermata ⇒ binding_mismatch ⇒ consenso rifiutato.
 *
 * L'evidenza citabile (challenge id, AAL raggiunto, driver) arriva da
 * RebelStepUp::confirmation() (P6, read-only). La consumazione ONE-SHOT resta del
 * modulo: la UNIQUE su iam_delegation_grants.consent_confirmation_id brucia la
 * conferma alla creazione della grant (rebel non consuma le conferme by design).
 *
 * Attivazione (config/iam-agents.php):
 *   'consent' => ['verifier' => \Padosoft\Iam\Agents\Consent\RebelStepUpConsentVerifier::class]
 * Il purpose (default `iam-delegation-grant`, kebab-case: i punti sono separatori di
 * path config) DEVE esistere in `rebel-step-up.purposes` con `sca.dynamic_linking`
 * attivo e `required_assurance` coerente con `iam-agents.consent.required_aal`.
 */
final class RebelStepUpConsentVerifier implements ConsentVerifier
{
    public function __construct(private readonly RebelStepUp $stepUp) {}

    public function challenge(SubjectRef $user, ConsentPayload $payload, ?SessionRef $session): array
    {
        // $session non serve qui: la liveness della sessione IAM è ri-verificata a OGNI
        // exchange (SessionRegistry::active nel grant RFC 8693) — il consenso rebel
        // vive sull'auth dell'app host, non sulla sessione IAM.
        $start = $this->stepUp->start($this->context($user, $payload));

        $expiresAt = StepUpChallenge::query()->whereKey($start->challengeId)->value('expires_at');

        return [
            'challenge_id' => $start->challengeId,
            'method' => $start->driver,
            'expires_at' => $expiresAt instanceof \DateTimeInterface
                ? $expiresAt->format(\DateTimeInterface::ATOM)
                : now()->addMinutes(10)->format(\DateTimeInterface::ATOM),
        ];
    }

    public function verifyAndConsume(SubjectRef $user, ConsentPayload $payload, string $challengeId, array $verification): ConsentEvidence
    {
        if ($challengeId === '') {
            throw new ConsentFailedException('challenge_id mancante.');
        }
        $code = $verification['code'] ?? null;
        if (!is_string($code) || $code === '') {
            throw new ConsentFailedException('Codice di verifica mancante.');
        }

        // Il contesto è RICOSTRUITO dai parametri presentati ORA: se differiscono da
        // quelli vincolati alla challenge, il binding hash non combacia e rebel
        // rifiuta (binding_mismatch) — il dynamic linking è enforcement, non fiducia.
        $context = $this->context($user, $payload);

        $result = $this->stepUp->confirm($challengeId, $code, $context);
        if (!$result->success) {
            throw new ConsentFailedException('Verifica step-up del consenso fallita'.($result->reason !== null ? " ({$result->reason})" : '').'.');
        }

        // P6: evidenza read-only (leggerla non consuma nulla). Deve riferirsi ESATTAMENTE
        // alla challenge confermata — mai un'altra conferma valida dello stesso purpose.
        $evidence = $this->stepUp->confirmation($context);
        if ($evidence === null || $evidence->id !== $challengeId) {
            throw new ConsentFailedException('Evidenza del consenso assente o non riferita alla challenge confermata.');
        }

        // AAL raggiunto: sconosciuto ⇒ fail-closed (mai degradare un requisito).
        $aal = is_string($evidence->achieved_assurance) ? Aal::tryFrom($evidence->achieved_assurance) : null;
        if ($aal === null) {
            throw new ConsentFailedException('AAL del consenso non riconosciuto: rifiuto fail-closed.');
        }
        if (!$aal->satisfies($this->requiredAal())) {
            throw new ConsentFailedException("AAL del consenso insufficiente ({$aal->value} < {$this->requiredAal()->value}).");
        }

        return new ConsentEvidence(confirmationId: $challengeId, aal: $aal);
    }

    private function context(SubjectRef $user, ConsentPayload $payload): StepUpContext
    {
        return new StepUpContext(
            // L'id del subject rebel è il SubjectRef completo ("user:42"): niente
            // collisioni tra tipi di soggetto diversi con lo stesso id numerico.
            subject: new GenericUser(['id' => (string) $user]),
            purpose: $this->purposeAction(),
            security: new SecurityContext(requestId: (string) Str::uuid()),
            transaction: new GenericBindingContext([
                'agent' => $payload->agentId,
                'scopes' => $payload->scopes, // già ordinati e dedupati da ConsentPayload
                'ttl' => $payload->ttlSeconds,
                'purpose' => $payload->purpose,
            ]),
        );
    }

    private function purposeAction(): string
    {
        $purpose = config('iam-agents.consent.purpose', 'iam-delegation-grant');

        return is_string($purpose) && $purpose !== '' ? $purpose : 'iam-delegation-grant';
    }

    private function requiredAal(): Aal
    {
        // NB: NON Aal::fromString — degrada l'ignoto ad AAL1 (fail-open per i REQUISITI).
        $aal = config('iam-agents.consent.required_aal', 'aal2');
        $parsed = is_string($aal) ? Aal::tryFrom($aal) : null;

        return $parsed ?? Aal::AAL2;
    }
}
