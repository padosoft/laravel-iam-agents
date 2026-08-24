<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Registry;

use Illuminate\Contracts\Events\Dispatcher;
use Padosoft\Iam\Agents\Audit\DelegationAudit;
use Padosoft\Iam\Agents\Events\AgentSuspended;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Contracts\Delegation\ActorRef;
use Padosoft\Iam\Contracts\Delegation\AgentLifecycle;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Implementazione della porta AgentLifecycle (contracts v1.4): il kill-switch
 * invocabile dai componenti di sicurezza (rebel-ai-guard su anomalie dello
 * stream delegation). SOLO suspend — la ri-attivazione resta umana (console).
 *
 * Idempotente: un agente già sospeso/ritirato non transita di nuovo (niente
 * doppio audit). Un agente ignoto è un no-op: la sospensione è un contenimento,
 * non deve mai lanciare dentro un detector.
 */
final class AgentLifecycleService implements AgentLifecycle
{
    public function __construct(
        private readonly DelegationAudit $audit,
        private readonly Dispatcher $events,
    ) {}

    public function suspend(SubjectRef $agent, string $reason, string $actor): void
    {
        if ($agent->type !== ActorRef::SUBJECT_TYPE) {
            return;
        }
        $row = Agent::query()->find($agent->id);
        if ($row === null || $row->status !== AgentStatus::Active->value) {
            return; // idempotente / contenimento: mai lanciare da qui
        }

        $row->fill(['status' => AgentStatus::Suspended->value, 'suspended_at' => now()])->save();

        $this->audit->agentLifecycle($row, 'suspended', new SubjectRef('service', $actor));
        $this->events->dispatch(new AgentSuspended($row->id, $row->name, $reason, $actor));
    }
}
