<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Events;

/**
 * Un agente è stato APPROVATO da un umano (gate: JWKS incollata, client OAuth
 * token-exchange-only creato, stato active). Consumer di riferimento:
 * laravel-ai-act-compliance, che lo iscrive nel risk register (art. 6).
 *
 * @property list<string> $maxScopes
 */
final readonly class AgentApproved
{
    /** @param  list<string>  $maxScopes */
    public function __construct(
        public string $agentId,
        public string $name,
        public ?string $operator,
        public array $maxScopes,
        public string $actor,
    ) {}
}
