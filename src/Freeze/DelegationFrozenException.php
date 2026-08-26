<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Freeze;

use RuntimeException;

/**
 * La delega è congelata (o il suo stato non è leggibile, che per un kill switch
 * è la stessa cosa: "non ho potuto verificare" non è "va bene").
 *
 * `reason` è il motivo MACCHINA (`delegation_frozen` / `freeze_state_unavailable`)
 * che finisce nell'audit; il testo umano del freeze viaggia in `freezeReason` e
 * non va mai restituito a un client OAuth — un rifiuto non deve raccontare a un
 * agente perché è stato fermato.
 */
final class DelegationFrozenException extends RuntimeException
{
    public const REASON_FROZEN = 'delegation_frozen';

    public const REASON_STATE_UNAVAILABLE = 'freeze_state_unavailable';

    public function __construct(
        public readonly string $reason,
        public readonly ?string $freezeId = null,
        public readonly ?string $freezeScope = null,
        public readonly ?string $freezeReason = null,
    ) {
        parent::__construct($reason);
    }

    public static function frozen(string $freezeId, string $scope, string $reason): self
    {
        return new self(self::REASON_FROZEN, $freezeId, $scope, $reason);
    }

    public static function stateUnavailable(): self
    {
        return new self(self::REASON_STATE_UNAVAILABLE);
    }

    /** Motivo per l'audit: mai esposto al client. */
    public function auditReason(): string
    {
        return $this->freezeId === null
            ? $this->reason
            : $this->reason.': '.$this->freezeId.' ('.(string) $this->freezeScope.')';
    }
}
