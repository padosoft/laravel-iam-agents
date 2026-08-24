<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Events;

/** Un agente è stato ritirato (stato terminale). */
final readonly class AgentRetired
{
    public function __construct(
        public string $agentId,
        public string $name,
        public string $actor,
    ) {}
}
