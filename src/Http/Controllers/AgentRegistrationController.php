<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Agents\Audit\DelegationAudit;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;

/**
 * Registrazione agentic (DCR RFC 7591, GATED): un agente può presentarsi da solo,
 * ma atterra SEMPRE in stato `pending` con ZERO grant e ZERO client attivo.
 * Diventa `active` (e ottiene il client private_key_jwt) SOLO con l'approvazione
 * umana in admin. Mai auto-provisioning: la registrazione è una candidatura.
 *
 * Threat model (documentato nel repo): spam di registrazioni → rate limit + flag
 * config OFF di default; squatting di nomi operator → l'operator dichiarato è
 * indicativo finché un admin non approva; escalation via metadata → il payload
 * è dati, mai istruzioni (nessun campo del payload tocca scope o permessi).
 */
final class AgentRegistrationController
{
    public function __construct(private readonly DelegationAudit $audit) {}

    public function register(Request $request): JsonResponse
    {
        if (config('iam-agents.registration.enabled', false) !== true) {
            // Modulo presente ma registrazione spenta: 404 esplicito (pattern iam-directory 409;
            // qui 404 per non rivelare la superficie a scanner non autorizzati).
            return new JsonResponse(['error' => 'not_found'], 404);
        }

        $name = $request->string('client_name')->toString();
        if ($name === '' || mb_strlen($name) > 128) {
            return new JsonResponse(['error' => 'invalid_client_metadata', 'error_description' => 'client_name richiesto (max 128)'], 400);
        }

        $authMethod = $request->string('token_endpoint_auth_method')->toString();
        if ($authMethod !== 'private_key_jwt') {
            return new JsonResponse(['error' => 'invalid_client_metadata', 'error_description' => 'token_endpoint_auth_method deve essere private_key_jwt'], 400);
        }
        $jwks = $request->input('jwks');
        if (!is_array($jwks) || !isset($jwks['keys']) || !is_array($jwks['keys']) || $jwks['keys'] === []) {
            return new JsonResponse(['error' => 'invalid_client_metadata', 'error_description' => 'jwks {keys:[…]} richieste'], 400);
        }

        $agent = Agent::query()->create([
            'id' => Agent::newId(),
            'name' => $name,
            'operator' => $request->string('operator')->toString() ?: null,
            // La candidatura NON sceglie i propri scope: max_scopes vuoto finché
            // un admin non li assegna all'approvazione (least privilege by default).
            'max_scopes' => [],
            'status' => AgentStatus::Pending->value,
        ]);
        $this->audit->agentRegistered($agent, 'dcr');

        // Risposta RFC 7591-shaped: la candidatura esiste, ma NON è utilizzabile.
        // Niente client_secret (mai), niente registration_access_token in MVP.
        return new JsonResponse([
            'client_id' => 'pending:'.$agent->id,
            'client_id_issued_at' => now()->timestamp,
            'token_endpoint_auth_method' => 'private_key_jwt',
            'grant_types' => [],
            'status' => 'pending_approval',
        ], 201);
    }
}
