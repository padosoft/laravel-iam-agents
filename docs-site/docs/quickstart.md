---
title: Quickstart
description: From composer require to a delegated tool call in five minutes — register an agent, collect consent, exchange, call, revoke.
---

# Quickstart

Five minutes, the whole loop: **register an agent → user consents → exchange → delegated call →
revoke → the next exchange fails**. This assumes a running [laravel-iam-server](https://doc.laravel-iam-server.padosoft.com)
host app.

## 1. Install next to the server

```bash
composer require padosoft/laravel-iam-agents
php artisan migrate
```

The module registers its RFC 8693 grant into the server's own `/oauth/token` at boot — no core fork,
no second issuer. It also announces itself on the server's `GET /capabilities` so consoles can show
their Agents/Delegations pages.

## 2. Configure consent (fail-closed until you do)

The default `ConsentVerifier` is the **Null** one: it refuses everything — an unconfigured module can
create **zero** grants. Pick a real verifier in `config/iam-agents.php`:

```php
'consent' => [
    // Built-in (no extra packages): IAM-native step-up, real single-use claim
    'verifier' => \Padosoft\Iam\Agents\Consent\IamNativeConsentVerifier::class,
    // Or PSD2-grade (requires padosoft/laravel-rebel-step-up ^0.2):
    // 'verifier' => \Padosoft\Iam\Agents\Consent\RebelStepUpConsentVerifier::class,
    'session_resolver' => \App\Iam\SessionCookieResolver::class, // where YOUR app keeps the IAM sid
],
```

See [Consent](/guides/consent) for what each verifier trades off.

## 3. Register and approve the agent

```bash
# Admin API (or use the Agents page in laravel-iam-console ≥ 1.2)
curl -X POST https://iam.example.com/api/iam/v1/agents \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "Order Copilot", "max_scopes": ["orders:read", "orders:draft"]}'

# Approval is the human gate: it pastes the agent's PUBLIC JWKS and creates the
# OAuth client — confidential, private_key_jwt, token-exchange grant ONLY.
curl -X POST https://iam.example.com/api/iam/v1/agents/{id}/approve \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jwks": {"keys": [{"kty": "EC", "crv": "P-256", "x": "…", "y": "…"}]}}'
```

Give the agent its own permissions in the PDP (it is an ordinary subject, `agent:{ulid}`): this is
the **agent half** of the intersection.

## 4. The user consents

Two steps, both on `iam/me/delegations` (session-authenticated, your app's guard):

```bash
# Step 1 — open the challenge, BOUND to these exact parameters
curl -X POST https://iam.example.com/iam/me/delegations/consent-challenge \
  -d '{"agent_id": "agt_…", "scopes": ["orders:read"], "ttl_seconds": 2592000,
       "purpose": "Draft weekly order proposals"}'
# → {"data": {"challenge_id": "…", "method": "…", "expires_at": "…"}}

# Step 2 — verify (e.g. the OTP the user received) and create the grant
curl -X POST https://iam.example.com/iam/me/delegations \
  -d '{"agent_id": "agt_…", "scopes": ["orders:read"], "ttl_seconds": 2592000,
       "purpose": "Draft weekly order proposals",
       "challenge_id": "…", "verification": {"code": "123456"}}'
```

Change any parameter between the two steps and the binding hash diverges: **refused**. The
confirmation is one-shot (`consent_confirmation_id` is UNIQUE).

## 5. Exchange

The orchestrator (never the LLM) holds the user's token and the agent's private key:

```php
use Padosoft\Iam\Contracts\Delegation\{TokenExchanger, TokenExchangeRequest};

$delegated = app(TokenExchanger::class)->exchange(new TokenExchangeRequest(
    subjectToken: $userAccessToken,
    scopes: ['orders:read'],
    audience: 'mcp://crm-tools',
));
// sub = user, act = agent, TTL ≤ 300s, non-refreshable. Re-exchange when it expires:
// that re-check IS how revocation lands.
```

(`TokenExchanger` ships in [laravel-iam-client ≥ 1.9](https://doc.laravel-iam-client.padosoft.com/guides/delegated-access);
the wire call is plain RFC 8693 §2.1 if you roll your own.)

## 6. The resource server enforces the intersection

```php
Route::get('/orders', ListOrders::class)->middleware('iam.can.delegated:shop:orders.read');
```

`iam.can.delegated` (laravel-iam-client) verifies the bearer via **mandatory introspection** and
decides user ∧ agent ∧ grant-still-active. Both identities land in the request attributes, in
Laravel Context (so in every log), and in the `delegation` audit stream.

## 7. Revoke — and watch the next exchange fail

```bash
curl -X DELETE https://iam.example.com/iam/me/delegations/{grantId}   # user, one click, no step-up
# or org-wide: POST /api/iam/v1/delegation-grants/{id}/revoke         # admin kill-switch
```

The next exchange returns `invalid_grant`; the next `checkDelegated` citing that `pds_dgr` denies.
Maximum staleness = the delegated token's TTL (≤ 5 minutes by default).
