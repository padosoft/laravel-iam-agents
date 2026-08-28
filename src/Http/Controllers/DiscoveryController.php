<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;

/**
 * Discovery agentic: il blocco `agent_auth` (protocollo aperto auth.md di WorkOS,
 * che ESTENDE la metadata RFC 8414) e il file AUTH.md — la "ricetta procedurale"
 * human/agent-readable per registrarsi e delegare.
 *
 * NB: auth.md prevede il blocco dentro /.well-known/oauth-authorization-server;
 * quella route è del server core (DiscoveryController IAM). Finché il server non
 * espone un hook di estensione della discovery, il blocco vive qui in un
 * well-known dedicato, cross-linkato da AUTH.md. (Ask upstream: P8.)
 */
final class DiscoveryController
{
    public function agentAuth(): JsonResponse
    {
        $base = rtrim((string) url('/'), '/');

        return new JsonResponse([
            'agent_auth' => [
                'skill' => $base.'/AUTH.md',
                'registration_endpoint' => config('iam-agents.registration.enabled', false) === true
                    ? $base.'/oauth/register'
                    : null,
                'token_endpoint' => $base.'/oauth/token',
                'grant_types_supported' => ['urn:ietf:params:oauth:grant-type:token-exchange'],
                'subject_token_types_supported' => ['urn:ietf:params:oauth:token-type:access_token'],
                'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
                'delegation' => [
                    'act_claim' => true,
                    'max_delegation_depth' => is_numeric($depth = config('iam-agents.max_delegation_depth', 1)) ? (int) $depth : 1,
                    'delegated_token_typ' => is_string($typ = config('iam-agents.tokens.typ', 'delegated+jwt')) ? $typ : 'delegated+jwt',
                    'introspection_required' => true,
                ],
            ],
        ]);
    }

    public function authMd(): Response
    {
        $base = rtrim((string) url('/'), '/');
        $registrationEnabled = config('iam-agents.registration.enabled', false) === true;

        $md = <<<MD
        # AUTH.md — Agent authentication & delegated access

        This service supports **delegated access for AI agents** (OAuth 2.0 Token Exchange,
        RFC 8693). Agents never receive a user's token: they exchange it for a short-lived,
        down-scoped token carrying both identities (`sub` = user, `act` = agent).

        ## How to act on behalf of a user

        1. **Be registered.** Your agent needs an approved identity here (status `active`).
        {$this->registrationLine($registrationEnabled, $base)}
        2. **Hold your own key.** Authentication is `private_key_jwt` (RFC 7523) — no shared
           secrets, no user credentials, ever.
        3. **Obtain user consent.** The user grants your agent specific scopes, for a purpose,
           with an expiry — confirmed via step-up. You cannot self-grant.
        4. **Exchange, don't impersonate.** POST `{$base}/oauth/token` with
           `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
           `subject_token=<the user's access token>`,
           `subject_token_type=urn:ietf:params:oauth:token-type:access_token`,
           your `client_assertion` (private_key_jwt), and optionally `scope` / `audience`.
        5. **Expect intersection.** Your effective authority is the strict intersection of
           the user's permissions and your granted scopes. Never the union.
        6. **Tokens are short-lived and not refreshable.** Re-exchange when they expire —
           that re-check is how revocation reaches you.

        ## What will get you denied

        - Forwarding a user token as your own credential (use the exchange).
        - An `actor_token` — the acting party is identified by your client
          authentication, so a second, unauthenticated claim of identity is refused.
        - Extending a chain past `max_delegation_depth`, or re-entering it (A→B→A).
        - A subject token without a live user session behind it.
        - Acting outside your granted scopes, or after the user revoked the grant.

        ## Machine-readable metadata

        See `{$base}/.well-known/agent-auth.json`.
        MD;

        return new Response($md, 200, ['Content-Type' => 'text/markdown; charset=utf-8']);
    }

    private function registrationLine(bool $enabled, string $base): string
    {
        return $enabled
            ? "   Self-registration: POST `{$base}/oauth/register` (RFC 7591 subset) — lands as\n   `pending`, activated only after human approval."
            : '   Self-registration is disabled: contact the operator of this service.';
    }
}
