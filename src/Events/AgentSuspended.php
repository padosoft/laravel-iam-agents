<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Events;

/**
 * Un agente è stato SOSPESO (kill-switch): da un admin o da un componente di
 * sicurezza via AgentLifecycle (es. rebel-ai-guard su anomalia dello stream
 * delegation). `actor` dice chi; `reason` perché.
 */
final readonly class AgentSuspended
{
    public function __construct(
        public string $agentId,
        public string $name,
        public string $reason,
        public string $actor,
    ) {}
}
