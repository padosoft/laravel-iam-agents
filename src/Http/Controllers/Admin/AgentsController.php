<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Http\Controllers\Admin;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Agents\Audit\DelegationAudit;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;

/**
 * Admin API del registry agenti: lifecycle (approve/suspend/retire), creazione
 * manuale, ricerca. L'approvazione di un agente `pending` (registrazione agentic)
 * è il GATE UMANO: crea/attiva il client OAuth (private_key_jwt, SOLO grant
 * token-exchange) e porta lo stato ad `active`. Mai auto-provisioning.
 */
final class AgentsController
{
    private const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';

    public function __construct(private readonly DelegationAudit $audit) {}

    public function index(Request $request): JsonResponse
    {
        $query = Agent::query()->orderByDesc('created_at');

        $status = $request->string('status')->toString();
        if ($status !== '') {
            $query->where('status', $status);
        }
        $operator = $request->string('operator')->toString();
        if ($operator !== '') {
            $query->where('operator', $operator);
        }

        return new JsonResponse(['data' => $query->limit(100)->get()]);
    }

    public function show(string $id): JsonResponse
    {
        $agent = Agent::query()->find($id);

        return $agent === null
            ? new JsonResponse(['error' => 'not_found'], 404)
            : new JsonResponse(['data' => $agent]);
    }

    /** Creazione manuale da admin (nasce comunque `pending`: l'approvazione è un passo esplicito). */
    public function store(Request $request): JsonResponse
    {
        $name = $request->string('name')->toString();
        $scopes = $request->input('max_scopes');
        if ($name === '' || !is_array($scopes) || $scopes === []) {
            return new JsonResponse(['error' => 'invalid_payload', 'message' => 'name e max_scopes richiesti'], 422);
        }

        $agent = Agent::query()->create([
            'id' => Agent::newId(),
            'name' => $name,
            'operator' => $request->string('operator')->toString() ?: null,
            'owner_type' => $request->string('owner_type')->toString() ?: null,
            'owner_id' => $request->string('owner_id')->toString() ?: null,
            'application_key' => $request->string('application_key')->toString() ?: null,
            'max_scopes' => array_values(array_filter($scopes, 'is_string')),
            'status' => AgentStatus::Pending->value,
            'organization_id' => $request->string('organization_id')->toString() ?: null,
        ]);
        $this->audit->agentRegistered($agent, 'admin');

        return new JsonResponse(['data' => $agent], 201);
    }

    /**
     * Il gate umano: pending → active. Crea (o riattiva) il client OAuth dell'agente:
     * confidential, private_key_jwt con le jwks fornite, SOLO grant token-exchange,
     * scope = max_scopes. Nessun secret condiviso, mai.
     */
    public function approve(Request $request, string $id): JsonResponse
    {
        $agent = Agent::query()->find($id);
        if ($agent === null) {
            return new JsonResponse(['error' => 'not_found'], 404);
        }
        if ($agent->statusEnum() === AgentStatus::Retired) {
            return new JsonResponse(['error' => 'agent_retired'], 409); // terminale
        }

        $jwks = $request->input('jwks');
        if (!is_array($jwks) || !isset($jwks['keys'])) {
            return new JsonResponse(['error' => 'invalid_payload', 'message' => 'jwks {keys:[…]} richieste (private_key_jwt)'], 422);
        }

        DB::transaction(function () use ($agent, $jwks): void {
            $clientId = $agent->client_id ?? 'cli_agent_'.$agent->id;
            $client = OauthClient::query()->firstOrNew(['client_id' => $clientId]);
            $client->fill([
                'name' => $agent->name,
                'redirect_uris' => [],
                'grants' => [self::TOKEN_EXCHANGE_GRANT],
                'scopes' => $agent->max_scopes,
                'is_confidential' => true,
                'is_first_party' => false,
                'organization_id' => $agent->organization_id,
                'token_endpoint_auth_method' => 'private_key_jwt',
                'jwks' => $jwks,
            ])->save();

            $agent->fill([
                'client_id' => $clientId,
                'status' => AgentStatus::Active->value,
                'approved_at' => now(),
                'approved_by' => is_string($actor = request()->attributes->get('iam_admin_actor')) ? $actor : 'admin',
            ])->save();
        });

        $this->audit->agentLifecycle($agent, 'approved');

        return new JsonResponse(['data' => $agent->refresh()]);
    }

    public function suspend(string $id): JsonResponse
    {
        return $this->transition($id, AgentStatus::Suspended, 'suspended', ['suspended_at' => now()]);
    }

    public function retire(string $id): JsonResponse
    {
        return $this->transition($id, AgentStatus::Retired, 'retired', ['retired_at' => now()]);
    }

    /**
     * @param  array<string, mixed>  $stamps
     */
    private function transition(string $id, AgentStatus $to, string $event, array $stamps): JsonResponse
    {
        $agent = Agent::query()->find($id);
        if ($agent === null) {
            return new JsonResponse(['error' => 'not_found'], 404);
        }
        if ($agent->statusEnum() === AgentStatus::Retired) {
            return new JsonResponse(['error' => 'agent_retired'], 409); // terminale, nessuna transizione
        }

        $agent->fill(['status' => $to->value] + $stamps)->save();
        $this->audit->agentLifecycle($agent, $event);

        return new JsonResponse(['data' => $agent]);
    }
}
