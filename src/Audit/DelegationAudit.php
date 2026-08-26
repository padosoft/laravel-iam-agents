<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Audit;

use Illuminate\Support\Facades\Context;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationElevationModel;
use Padosoft\Iam\Agents\Models\DelegationFreezeModel;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Agents\Support\RunCorrelation;
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
 *
 * Ogni scrittura passa da {@see self::record()}, che allega — quando c'è — l'id
 * del run AI dentro cui l'evento è avvenuto (§10: "chi ha fatto cosa, per conto
 * di chi", più il *lavoro* a cui appartiene). Senza, la console può solo
 * ordinare gli eventi per timestamp e sperare: due agenti che scambiano nello
 * stesso secondo diventano indistinguibili proprio quando serve distinguerli.
 */
final class DelegationAudit
{
    public const STREAM = 'delegation';

    public function __construct(private readonly AuditRecorder $recorder) {}

    /**
     * Unico punto di scrittura: correla l'evento al run AI in corso, se c'è.
     *
     * Gli id vivono nel Laravel Context (idratato da `IamCanDelegated`, stampato
     * da {@see RunCorrelation} sugli eventi di step di laravel/ai ≥ 0.11), quindi
     * arrivano gratis anche dai job accodati — Context si deidrata e reidrata da
     * solo. Su un'app senza delega attiva, o senza SDK, il contesto non esiste e
     * questo metodo è un passthrough: un evento non si inventa una correlazione.
     *
     * NON sovrascrive una chiave già presente nel metadata del chiamante: se un
     * emettitore sa qualcosa di più preciso sul run, la sua versione vince.
     *
     * @param  array<string, mixed>  $event
     */
    private function record(array $event): void
    {
        $context = Context::get(RunCorrelation::CONTEXT_KEY);

        if (is_array($context)) {
            $correlation = array_filter(
                [
                    'invocation_id' => $context['invocation_id'] ?? null,
                    'parent_invocation_id' => $context['parent_invocation_id'] ?? null,
                    'parent_tool_invocation_id' => $context['parent_tool_invocation_id'] ?? null,
                ],
                static fn ($value): bool => is_string($value) && $value !== '',
            );

            if ($correlation !== []) {
                $metadata = $event['metadata_json'] ?? [];
                $event['metadata_json'] = is_array($metadata)
                    ? [...$correlation, ...$metadata]
                    : $correlation;
            }
        }

        $this->recorder->record($event);
    }

    public function agentRegistered(Agent $agent, string $via): void
    {
        $this->record([
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
        $this->record([
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
        $this->record([
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
        $this->record([
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
     * Kill switch: la delega è stata congelata da UN admin.
     *
     * `risk_level` alto non perché congelare sia pericoloso, ma perché è il
     * segnale che qualcosa lo era: questo record è il primo che un incident
     * responder cerca.
     */
    public function freezeApplied(DelegationFreezeModel $freeze): void
    {
        $this->record([
            'stream' => self::STREAM,
            'event_type' => 'iam.delegation.freeze.applied',
            'target_type' => 'delegation_freeze',
            'target_id' => $freeze->id,
            'risk_level' => 'high',
            'metadata_json' => array_filter([
                'freeze_id' => $freeze->id,
                'scope' => $freeze->scope,
                'scope_id' => $freeze->scope_id,
                'reason' => $freeze->reason,
                'frozen_by' => $freeze->frozen_by,
                'required_quorum' => $freeze->required_quorum,
            ], static fn ($v): bool => $v !== null),
        ]);
    }

    /**
     * Una approvazione alla rimozione. Auditata SEMPRE, anche quando il quorum non
     * è ancora completo e anche quando è un doppione: "chi ha voluto far ripartire
     * gli agenti" è una domanda a cui si risponde con l'elenco completo, non con
     * il solo nome di chi ha dato l'ultima firma.
     */
    public function freezeLiftApproved(DelegationFreezeModel $freeze, SubjectRef $approver, int $collected, bool $duplicate): void
    {
        $this->record([
            'stream' => self::STREAM,
            'event_type' => 'iam.delegation.freeze.lift_approved',
            'actor_user_id' => $approver->type === 'user' ? $approver->id : null,
            'target_type' => 'delegation_freeze',
            'target_id' => $freeze->id,
            'risk_level' => 'medium',
            'metadata_json' => [
                'freeze_id' => $freeze->id,
                'approver' => (string) $approver,
                'approvals' => $collected,
                'required_quorum' => $freeze->required_quorum,
                'duplicate' => $duplicate,
            ],
        ]);
    }

    /** Quorum raggiunto: la delega riparte. */
    public function freezeLifted(DelegationFreezeModel $freeze, int $approvals): void
    {
        $this->record([
            'stream' => self::STREAM,
            'event_type' => 'iam.delegation.freeze.lifted',
            'target_type' => 'delegation_freeze',
            'target_id' => $freeze->id,
            'risk_level' => 'high',
            'metadata_json' => [
                'freeze_id' => $freeze->id,
                'scope' => $freeze->scope,
                'approvals' => $approvals,
                'required_quorum' => $freeze->required_quorum,
                'lifted_by' => $freeze->lifted_by,
            ],
        ]);
    }

    /** Richiesta di JIT elevation aperta (scope extra + reason, finestra pending). */
    public function elevationRequested(DelegationElevationModel $elevation, string $agentName): void
    {
        $this->record([
            'stream' => self::STREAM,
            'event_type' => 'iam.delegation.elevation.requested',
            'target_type' => 'delegation_elevation',
            'target_id' => $elevation->id,
            'risk_level' => 'medium',
            'metadata_json' => [
                'grant_id' => $elevation->grant_id,
                'agent_name' => $agentName,
                'requested_scopes' => $elevation->requested_scopes,
                'reason' => $elevation->reason,
            ],
        ]);
    }

    /** Esito della consegna out-of-band (rebel-channels): mai inghiottita muta. */
    public function elevationNotified(DelegationElevationModel $elevation, bool $delivered, ?string $error = null): void
    {
        $this->record([
            'stream' => self::STREAM,
            'event_type' => $delivered ? 'iam.delegation.elevation.notified' : 'iam.delegation.elevation.notify_failed',
            'target_type' => 'delegation_elevation',
            'target_id' => $elevation->id,
            'risk_level' => $delivered ? 'low' : 'medium',
            'metadata_json' => array_filter([
                'grant_id' => $elevation->grant_id,
                'error' => $error,
            ], static fn ($v): bool => $v !== null),
        ]);
    }

    /** Decisione del delegante: approved (con evidenza ri-consenso) o denied. */
    public function elevationDecided(DelegationElevationModel $elevation, string $decision): void
    {
        $this->record([
            'stream' => self::STREAM,
            'event_type' => 'iam.delegation.elevation.'.$decision,
            'target_type' => 'delegation_elevation',
            'target_id' => $elevation->id,
            'risk_level' => $decision === 'approved' ? 'medium' : 'low',
            'metadata_json' => array_filter([
                'grant_id' => $elevation->grant_id,
                'requested_scopes' => $elevation->requested_scopes,
                'consent_confirmation_id' => $elevation->consent_confirmation_id,
                'consent_aal' => $elevation->consent_aal,
            ], static fn ($v): bool => $v !== null),
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
        $this->record([
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
