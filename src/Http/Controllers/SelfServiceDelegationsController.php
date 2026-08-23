<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Agents\Audit\DelegationAudit;
use Padosoft\Iam\Agents\Consent\ConsentFailedException;
use Padosoft\Iam\Agents\Consent\ConsentPayload;
use Padosoft\Iam\Agents\Consent\ConsentVerifier;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Agents\Support\DelegationSessionResolver;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStore;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Self-service "le mie deleghe": lista (con evidenza e scadenze), consenso in due
 * passi (challenge vincolata ai parametri → verifica+creazione), revoca one-click.
 * Revocare è SEMPRE più facile che concedere: la revoca non richiede step-up.
 */
final class SelfServiceDelegationsController
{
    public function __construct(
        private readonly ConsentVerifier $consent,
        private readonly DelegationSessionResolver $sessions,
        private readonly DelegationGrantStore $store,
        private readonly DelegationAudit $audit,
    ) {}

    public function index(Request $request): JsonResponse
    {
        $user = $this->subject($request);

        $grants = [];
        foreach ($this->store->listFor($user) as $grant) {
            $grants[] = [
                'id' => $grant->id,
                'agent' => (string) $grant->agent,
                'scopes' => $grant->scopes,
                'purpose' => $grant->purpose,
                'status' => $grant->status->value,
                'expires_at' => $grant->expiresAt->format(\DateTimeInterface::ATOM),
                'created_at' => $grant->createdAt->format(\DateTimeInterface::ATOM),
                'consent_aal' => $grant->consentAal?->value,
                'revoked_at' => $grant->revokedAt?->format(\DateTimeInterface::ATOM),
            ];
        }

        return new JsonResponse(['data' => $grants]);
    }

    /** Passo 1: apre la challenge di consenso VINCOLATA ai parametri richiesti. */
    public function consentChallenge(Request $request): JsonResponse
    {
        $user = $this->subject($request);
        try {
            $payload = $this->payloadFrom($request);
        } catch (\InvalidArgumentException $e) {
            return new JsonResponse(['error' => 'invalid_payload', 'message' => $e->getMessage()], 422);
        }

        try {
            $challenge = $this->consent->challenge($user, $payload, $this->sessions->resolve($request));
        } catch (ConsentFailedException $e) {
            return new JsonResponse(['error' => 'consent_unavailable', 'message' => $e->getMessage()], 422);
        }

        return new JsonResponse(['data' => $challenge]);
    }

    /**
     * Passo 2: verifica la challenge (stessi parametri, o binding mismatch) e crea
     * la grant. `consent_confirmation_id` è UNIQUE ⇒ la stessa conferma non può
     * creare due grant (one-shot anche sotto concorrenza).
     */
    public function store(Request $request): JsonResponse
    {
        $user = $this->subject($request);
        try {
            $payload = $this->payloadFrom($request);
        } catch (\InvalidArgumentException $e) {
            return new JsonResponse(['error' => 'invalid_payload', 'message' => $e->getMessage()], 422);
        }

        $agent = Agent::query()->find($payload->agentId);
        if ($agent === null || $agent->statusEnum() !== AgentStatus::Active) {
            return new JsonResponse(['error' => 'agent_not_active'], 422);
        }
        $outsideCeiling = array_diff($payload->scopes, array_filter($agent->max_scopes, 'is_string'));
        if ($outsideCeiling !== []) {
            return new JsonResponse(['error' => 'scopes_exceed_agent_ceiling', 'scopes' => array_values($outsideCeiling)], 422);
        }

        $maxTtl = $this->maxTtlSeconds();
        if ($payload->ttlSeconds > $maxTtl) {
            return new JsonResponse(['error' => 'ttl_exceeds_maximum', 'max_ttl_seconds' => $maxTtl], 422);
        }

        $challengeId = $request->string('challenge_id')->toString();
        $raw = $request->input('verification');
        $verification = [];
        if (is_array($raw)) {
            foreach ($raw as $key => $value) {
                if (is_string($key)) {
                    $verification[$key] = $value;
                }
            }
        }

        try {
            $evidence = $this->consent->verifyAndConsume($user, $payload, $challengeId, $verification);
        } catch (ConsentFailedException $e) {
            return new JsonResponse(['error' => 'consent_failed', 'message' => $e->getMessage()], 422);
        }

        $grant = DB::transaction(function () use ($user, $payload, $evidence): DelegationGrantModel {
            $grant = DelegationGrantModel::query()->create([
                'id' => DelegationGrantModel::newId(),
                'user_type' => $user->type,
                'user_id' => $user->id,
                'agent_id' => $payload->agentId,
                'scopes' => $payload->scopes,
                'purpose' => $payload->purpose,
                'status' => DelegationGrantStatus::Active->value,
                'expires_at' => now()->addSeconds($payload->ttlSeconds),
                'consent_confirmation_id' => $evidence->confirmationId, // UNIQUE ⇒ one-shot
                'consent_aal' => $evidence->aal->value,
            ]);
            $this->audit->grantCreated($grant);

            return $grant;
        });

        return new JsonResponse(['data' => ['id' => $grant->id]], 201);
    }

    /** Revoca one-click della PROPRIA delega (idempotente; mai step-up per revocare). */
    public function destroy(Request $request, string $grantId): JsonResponse
    {
        $user = $this->subject($request);

        // Ownership: si revoca solo una delega propria (404 su altrui: niente esistenza).
        $grant = $this->store->find($grantId);
        if ($grant === null || (string) $grant->user !== (string) $user) {
            return new JsonResponse(['error' => 'not_found'], 404);
        }

        $this->store->revoke($grantId, $user);

        return new JsonResponse(status: 204);
    }

    private function subject(Request $request): SubjectRef
    {
        $user = $request->user();
        abort_if($user === null, 401);
        $id = $user->getAuthIdentifier();

        return new SubjectRef('user', is_scalar($id) ? (string) $id : '');
    }

    private function payloadFrom(Request $request): ConsentPayload
    {
        $scopes = $request->input('scopes');

        return new ConsentPayload(
            agentId: $request->string('agent_id')->toString(),
            scopes: is_array($scopes) ? array_values(array_filter($scopes, 'is_string')) : [],
            ttlSeconds: $request->integer('ttl_seconds'),
            purpose: $request->string('purpose')->toString(),
        );
    }

    private function maxTtlSeconds(): int
    {
        $days = config('iam-agents.grants.max_ttl_days', 30);

        return (is_numeric($days) ? (int) $days : 30) * 86400;
    }
}
