<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Events;

use Padosoft\Iam\Contracts\Delegation\DelegationGrant;

/**
 * Una delega è stata consentita (consenso step-up verificato, grant Active).
 * Consumer di riferimento: laravel-ai-act-compliance, che la registra come item
 * di human oversight (art. 14) — il consenso È l'atto di supervisione umana.
 */
final readonly class DelegationGrantCreated
{
    public function __construct(
        public DelegationGrant $grant,
        public string $agentName,
    ) {}
}
