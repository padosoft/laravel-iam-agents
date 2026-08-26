<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Freeze;

/**
 * Esito di una approvazione alla rimozione: il freeze è ripartito, oppure quante
 * approvazioni distinte mancano ancora.
 *
 * Restituire il conteggio anche quando NON si è ancora sbloccato è deliberato: un
 * admin che approva deve vedere subito se ha completato il quorum o se sta ancora
 * aspettando qualcuno, altrimenti l'unico modo per saperlo è provare a usare la
 * delega.
 */
final class LiftOutcome
{
    public function __construct(
        public readonly bool $lifted,
        public readonly int $collected,
        public readonly int $required,
        public readonly bool $alreadyApproved = false,
    ) {}

    public function remaining(): int
    {
        return max(0, $this->required - $this->collected);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'lifted' => $this->lifted,
            'approvals' => $this->collected,
            'required_quorum' => $this->required,
            'remaining_approvals' => $this->remaining(),
            'already_approved' => $this->alreadyApproved,
        ];
    }
}
