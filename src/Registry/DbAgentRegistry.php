<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Registry;

use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Contracts\Delegation\ActorRef;
use Padosoft\Iam\Contracts\Delegation\AgentDescriptor;
use Padosoft\Iam\Contracts\Delegation\AgentRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Registry degli agenti su DB. `null` per soggetti non-agent o ignoti ⇒ deny a valle.
 */
final class DbAgentRegistry implements AgentRegistry
{
    public function find(SubjectRef $agent): ?AgentDescriptor
    {
        if ($agent->type !== ActorRef::SUBJECT_TYPE) {
            return null;
        }

        return Agent::query()->find($agent->id)?->toDescriptor();
    }

    /** Lookup per client OAuth (l'exchange autentica l'agente via private_key_jwt del suo client). */
    public function findByClientId(string $clientId): ?Agent
    {
        if ($clientId === '') {
            return null;
        }

        return Agent::query()->where('client_id', $clientId)->first();
    }
}
