<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Audit;

use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Pii\AuditRecorder;

/**
 * Emettitore dell'audit di delega: stream dedicato `delegation` sulla hash-chain
 * tamper-evident del server (stesso store, parallelo allo `stream=ai` di iam-ai).
 * Risponde a "chi ha fatto cosa, per conto di chi": ogni evento porta
 * actor_agent_id + il subject delegante nel metadata.
 *
 * Passa dall'AuditRecorder del server (non dall'appender diretto): oltre alla
 * sigillatura in catena, ogni evento viene così SPINTO alle subscription webhook
 * attive (P2) — è il canale con cui una revoca di grant raggiunge PEP e agent
 * senza attendere un poll.
 *
 * NB naming metadata: `grant_id`/`*_confirmation_id` — MAI chiavi con substring
 * `token` (l'admin API redige per substring).
 */
final class DelegationAudit
{
    public const STREAM = 'delegation';

    public function __construct(private readonly AuditRecorder $recorder) {}

    public function agentRegistered(Agent $agent, string $via): void
    {
        $this->recorder->record([
            'stream' => self::STREAM,
            'event_type' => 'iam.delegation.agent.registered',
            'actor_agent_id' => $agent->id,
            'target_type' => 'agent',
            'target_id' => $agent->id,
            'organization_id' => $agent->organization_id,
            'metadata_json' => ['via' => $via, 'operator' => $agent->operator, 'status' => $agent->status],
        ]);
    }

    public function agentLifecycle(Agent $agent, string $transition, ?SubjectRef $by = null): void
    {
        $this->recorder->record([
            'stream' => self::STREAM,
            'event_type' => 'iam.delegation.agent.'.$transition,
            'actor_user_id' => $by?->type === 'user' ? $by->id : null,
            'actor_agent_id' => $agent->id,
            'target_type' => 'agent',
            'target_id' => $agent->id,
            'organization_id' => $agent->organization_id,
            'metadata_json' => ['by' => $by !== null ? (string) $by : null, 'status' => $agent->status],
        ]);
    }

    public function grantCreated(DelegationGrantModel $grant): void
    {
        $this->recorder->record([
            'stream' => self::STREAM,
            'event_type' => 'iam.delegation.grant.created',
            'actor_user_id' => $grant->user_type === 'user' ? $grant->user_id : null,
            'actor_agent_id' => $grant->agent_id,
            'actor_assurance' => $grant->consent_aal,
            'target_type' => 'delegation_grant',
            'target_id' => $grant->id,
            'metadata_json' => [
                'grant_id' => $grant->id,
                'user' => $grant->user_type.':'.$grant->user_id,
                'scopes' => $grant->scopes,
                'purpose' => $grant->purpose,
                'expires_at' => $grant->expires_at->toIso8601String(),
                'consent_confirmation_id' => $grant->consent_confirmation_id,
            ],
        ]);
    }

    public function grantRevoked(DelegationGrantModel $grant, SubjectRef $revokedBy): void
    {
        $this->recorder->record([
            'stream' => self::STREAM,
            'event_type' => 'iam.delegation.grant.revoked',
            'actor_user_id' => $revokedBy->type === 'user' ? $revokedBy->id : null,
            'actor_agent_id' => $grant->agent_id,
            'target_type' => 'delegation_grant',
            'target_id' => $grant->id,
            'metadata_json' => [
                'grant_id' => $grant->id,
                'user' => $grant->user_type.':'.$grant->user_id,
                'revoked_by' => (string) $revokedBy,
            ],
        ]);
    }

    /**
     * Ogni exchange, riuscito O rifiutato (il motivo del rifiuto è parte dell'audit:
     * i tentativi respinti sono il segnale per l'anomaly detection).
     *
     * @param  list<string>  $scopes
     */
    public function exchange(string $agentId, ?string $userSubject, bool $issued, array $scopes = [], ?string $grantId = null, ?string $refusalReason = null): void
    {
        $this->recorder->record([
            'stream' => self::STREAM,
            'event_type' => $issued ? 'iam.delegation.exchange.issued' : 'iam.delegation.exchange.refused',
            'actor_agent_id' => $agentId,
            'target_type' => $grantId !== null ? 'delegation_grant' : null,
            'target_id' => $grantId,
            'risk_level' => $issued ? 'low' : 'medium',
            'metadata_json' => array_filter([
                'grant_id' => $grantId,
                'user' => $userSubject,
                'scopes' => $scopes !== [] ? $scopes : null,
                'refusal_reason' => $refusalReason,
            ], static fn ($v): bool => $v !== null),
        ]);
    }
}
