<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Consent;

use Padosoft\Iam\Contracts\Identity\SessionRef;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Default fail-closed: NESSUNA grant creabile finché non configuri un verifier reale
 * (`iam-agents.consent.verifier`). Il modulo installato ma non configurato non
 * concede nulla — mai un consenso implicito.
 */
final class NullConsentVerifier implements ConsentVerifier
{
    private const MESSAGE = 'Nessun ConsentVerifier configurato (iam-agents.consent.verifier): la creazione di deleghe è disabilitata (fail-closed).';

    public function challenge(SubjectRef $user, ConsentPayload $payload, ?SessionRef $session): array
    {
        throw new ConsentFailedException(self::MESSAGE);
    }

    public function verifyAndConsume(SubjectRef $user, ConsentPayload $payload, string $challengeId, array $verification): ConsentEvidence
    {
        throw new ConsentFailedException(self::MESSAGE);
    }
}
