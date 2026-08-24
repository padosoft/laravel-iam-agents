<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Events;

use Padosoft\Iam\Contracts\Delegation\DelegationGrant;

/**
 * Una delega è stata revocata (dall'utente o da un admin). Il VO porta già
 * revokedBy/revokedAt. Consumer di riferimento: laravel-ai-act-compliance
 * (la revoca è un atto di oversight umano, art. 14).
 */
final readonly class DelegationGrantRevoked
{
    public function __construct(
        public DelegationGrant $grant,
        public string $agentName,
    ) {}
}
