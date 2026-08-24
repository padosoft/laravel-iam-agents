<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Consent;

use Padosoft\Iam\Contracts\Assurance\Aal;

/**
 * L'evidenza di un consenso verificato: l'id conferma (citato dalla grant, UNIQUE ⇒
 * one-shot) e l'AAL effettivamente raggiunto. La grant la conserva, l'audit la cita.
 */
final readonly class ConsentEvidence
{
    public function __construct(
        public string $confirmationId,
        public Aal $aal,
    ) {
        if ($this->confirmationId === '') {
            throw new \InvalidArgumentException('ConsentEvidence senza confirmationId.');
        }
    }
}
