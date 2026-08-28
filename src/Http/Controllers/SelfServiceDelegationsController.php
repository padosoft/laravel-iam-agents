<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Agents\Audit\DelegationAudit;
use Padosoft\Iam\Agents\Consent\ConsentFailedException;
use Padosoft\Iam\Agents\Consent\ConsentPayload;
use Padosoft\Iam\Agents\Consent\ConsentPreview;
use Padosoft\Iam\Agents\Consent\ConsentVerifier;
use Padosoft\Iam\Agents\Elevation\DelegationElevationService;
use Padosoft\Iam\Agents\Elevation\ElevationException;
use Padosoft\Iam\Agents\Events\DelegationGrantCreated;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Agents\Models\DelegationReceiptModel;
use Padosoft\Iam\Agents\Support\DelegationSessionResolver;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationBudget;
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

    /**
     * "Cosa hanno fatto i miei agenti": la timeline delle ricevute firmate.
     *
     * Ogni riga porta il proprio JWS, così l'utente può esportarla e farla
     * verificare da chiunque col JWKS pubblico — senza chiedere niente a noi. È
     * la differenza fra un audit (che è nostro, e serve agli admin) e una
     * ricevuta (che è dell'utente).
     */
    public function receipts(Request $request): JsonResponse
    {
        $user = $this->subject($request);

        $rows = DelegationReceiptModel::query()
            ->where('subject_type', $user->type)
            ->where('subject_id', $user->id)
            ->orderByDesc('issued_at')
            ->limit(100)
            ->get();

        return new JsonResponse([
            'data' => $rows->map(static fn (DelegationReceiptModel $r): array => [
                'id' => $r->id,
                'agent' => 'agent:'.$r->agent_id,
                'grant_id' => $r->grant_id,
                'action' => $r->action,
                'resource' => $r->resource,
                'outcome' => $r->outcome,
                'decision_id' => $r->decision_id,
                'issued_at' => $r->issued_at->toDateTimeImmutable()->format(\DateTimeInterface::ATOM),
                'payload_digest' => $r->payload_digest,
                'receipt' => $r->jws,
            ])->all(),
        ]);
    }

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
                'budget' => $grant->budget?->toArray(),
            ];
        }

        return new JsonResponse([
            'data' => $grants,
            // Richieste di JIT elevation in attesa della decisione del delegante.
            'pending_elevations' => app(DelegationElevationService::class)->pendingFor($user),
        ]);
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
     * Passo 0 (opzionale, prima della challenge): che cosa sto concedendo DAVVERO.
     *
     * Una schermata che dice "orders:read" chiede di approvare un nome. Questa
     * ritorna le RISORSE concrete che l'agente potrebbe toccare per conto di chi
     * sta guardando — l'intersezione fra ciò che raggiunge l'utente e ciò che
     * raggiunge l'agente, cioè l'autorita' effettiva della delega.
     *
     * Non e' un'autorizzazione: e' una fotografia scattata adesso, e la verita'
     * resta il PDP a ogni richiesta. Il troncamento e' dichiarato (`total`,
     * `truncated`) proprio perche' un preview che sottostima il raggio farebbe
     * sembrare piccola una delega grande.
     */
    public function consentPreview(Request $request, ConsentPreview $preview): JsonResponse
    {
        $agentId = $request->string('agent_id')->toString();
        if ($agentId === '') {
            return new JsonResponse(['error' => 'invalid_payload', 'message' => '`agent_id` mancante.'], 422);
        }

        $relations = $request->input('relations');
        $relations = is_array($relations) ? array_values(array_filter($relations, 'is_string')) : [];
        if ($relations === []) {
            return new JsonResponse(['error' => 'invalid_payload', 'message' => '`relations` non puo\' essere vuoto.'], 422);
        }

        return new JsonResponse(['data' => $preview->forGrant(
            $this->subject($request),
            new SubjectRef('agent', $agentId),
            $relations,
        )]);
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
                'budget' => $payload->budget?->toArray(),
                'status' => DelegationGrantStatus::Active->value,
                'expires_at' => now()->addSeconds($payload->ttlSeconds),
                'consent_confirmation_id' => $evidence->confirmationId, // UNIQUE ⇒ one-shot
                'consent_aal' => $evidence->aal->value,
            ]);
            $this->audit->grantCreated($grant);

            return $grant;
        });

        event(new DelegationGrantCreated($grant->toContract(), $agent->name));

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

    /** Passo 1 dell'approvazione JIT: challenge step-up vincolata agli scope extra. */
    public function elevationChallenge(Request $request, string $elevationId): JsonResponse
    {
        $user = $this->subject($request);
        try {
            $challenge = app(DelegationElevationService::class)
                ->approveChallenge($elevationId, $user, $this->sessions->resolve($request));
        } catch (ElevationException|ConsentFailedException $e) {
            return new JsonResponse(['error' => 'elevation_unavailable', 'message' => $e->getMessage()], 422);
        }

        return new JsonResponse(['data' => $challenge]);
    }

    /** Passo 2: verifica il RI-consenso e (one-shot) estende la grant. */
    public function elevationApprove(Request $request, string $elevationId): JsonResponse
    {
        $user = $this->subject($request);
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
            app(DelegationElevationService::class)->approve(
                $elevationId,
                $user,
                $request->string('challenge_id')->toString(),
                $verification,
            );
        } catch (ElevationException $e) {
            return new JsonResponse(['error' => 'elevation_failed', 'message' => $e->getMessage()], 422);
        }

        return new JsonResponse(['data' => ['id' => $elevationId, 'status' => 'approved']]);
    }

    /** Negare è one-click: mai step-up per rifiutare un'estensione di autorità. */
    public function elevationDeny(Request $request, string $elevationId): JsonResponse
    {
        $user = $this->subject($request);
        try {
            app(DelegationElevationService::class)->deny($elevationId, $user);
        } catch (ElevationException $e) {
            return new JsonResponse(['error' => 'elevation_failed', 'message' => $e->getMessage()], 422);
        }

        return new JsonResponse(['data' => ['id' => $elevationId, 'status' => 'denied']]);
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

        $budgetInput = $request->input('budget');
        // Budget opzionale (v1.1): quando presente ENTRA nel binding del consenso —
        // l'utente approva anche l'intensità, non solo l'autorità.
        $budget = is_array($budgetInput) && $budgetInput !== [] ? DelegationBudget::fromArray($budgetInput) : null;

        return new ConsentPayload(
            agentId: $request->string('agent_id')->toString(),
            scopes: is_array($scopes) ? array_values(array_filter($scopes, 'is_string')) : [],
            ttlSeconds: $request->integer('ttl_seconds'),
            purpose: $request->string('purpose')->toString(),
            budget: $budget,
        );
    }

    private function maxTtlSeconds(): int
    {
        $days = config('iam-agents.grants.max_ttl_days', 30);

        return (is_numeric($days) ? (int) $days : 30) * 86400;
    }
}
