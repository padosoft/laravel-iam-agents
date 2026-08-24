---
title: Exchange & verify
description: Performing the RFC 8693 exchange (server-side pipeline, client-side call) and verifying delegated bearers on resource servers.
---

# Exchange & verify

## The server-side pipeline

`POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, the agent
authenticating via `private_key_jwt`. Every step fails closed and every outcome — issued **or**
refused — is audited on `stream=delegation`:

1. **Client assertion** valid (RFC 7523, single-use `jti`) and the client belongs to an agent in
   status `active`;
2. **`subject_token`** valid, its user not disabled, and its **session still alive** in the
   SessionRegistry — a subject token without `sid` is refused: delegation requires a human session
   behind it;
3. A **delegation grant** for (user, agent) exists and is `Active`, not expired, not revoked;
4. **Scopes** = `requested ∩ grant ∩ agent.max_scopes` — empty intersection ⇒ `invalid_scope`;
5. **Depth**: `actor_token` refused while `max_delegation_depth` is 1 (clean `invalid_request` —
   wire-conformant, so v2 multi-hop is non-breaking).

The issued token: ES256 with the server's signer/JWKS, `typ: delegated+jwt`, claims `sub` (user),
`act` (agent), `pds_dgr` (grant id), `aud` (when requested via `audience`/`resource`), TTL from
`iam-agents.tokens.delegated_ttl` (default 300 s, hard cap 900), **no refresh token**.

## Client side: `TokenExchanger`

[`laravel-iam-client` ≥ 1.9](https://doc.laravel-iam-client.padosoft.com/guides/delegated-access)
ships `HttpTokenExchanger` (bound to the `TokenExchanger` contract), authenticating with the same
`private_key_jwt` config the app already has — an agent has **one** identity:

```php
use Padosoft\Iam\Client\Auth\TokenExchangeFailedException;
use Padosoft\Iam\Contracts\Delegation\{TokenExchanger, TokenExchangeRequest};

try {
    $delegated = app(TokenExchanger::class)->exchange(new TokenExchangeRequest(
        subjectToken: $userAccessToken,   // held by the BACKEND. The LLM never sees any token.
        scopes: ['orders:read'],
        audience: 'mcp://crm-tools',
    ));
} catch (TokenExchangeFailedException $e) {
    match ($e->error) {
        'invalid_grant' => $this->haltRun(),      // revoked / suspended / session dead
        'invalid_scope' => $this->narrowAsk(),    // outside the intersection
        default => throw $e,
    };
}
```

No caching, no refresh — deliberately. Failures **throw**; a degraded token is never returned.

## Resource server: verify the delegated bearer

```php
Route::get('/orders', ListOrders::class)->middleware('iam.can.delegated:shop:orders.read');
```

The client SDK's PEP is **act-aware from day one**: a delegated bearer is detected (by `typ` or
`act`), verified via **mandatory introspection** (session liveness included), decided on the
intersection (`/decisions/check-delegated` or the in-process engine), **never cached**, and the
delegation context lands in the request attributes *and* Laravel Context for every downstream log
and queued job. A malformed `act` **throws** — no degradation to a single-subject check.

For an MCP tool server, request the token with `audience: "mcp://your-server"` and validate `aud` —
a token minted for another audience is refused before any scope logic runs.

## Errors

Every refusal this pipeline can produce, with causes and fixes:
[Troubleshooting (RFC 8693 errors)](/reference/troubleshooting).
