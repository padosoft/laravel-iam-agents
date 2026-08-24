---
title: Cookbook
description: Recipes — a flow-ai bounded agent with delegated identity, an MCP tool server with audience-scoped tokens, a mobile backend orchestrator.
---

# Cookbook

## Recipe 1 — flow-ai bounded agent acting for the run's user

[`laravel-flow-ai` ≥ 1.1](https://github.com/padosoft/laravel-flow-ai) has the
`DelegatedIdentityResolver` seam: the runtime resolves a delegated token **before the first tool /
MCP call** and re-exchanges on expiry mid-run.

```php
// Start the run knowing WHO it acts for (flow ≥ 2.2: subject on FlowExecutionOptions)
$run = Flow::run('weekly-orders', $input, FlowExecutionOptions::make(subject: 'user:42'));
```

Wire a resolver that calls `TokenExchanger` with the run's subject; on `invalid_grant` throw
`GrantRevokedException` — the run **halts before the next tool call** (a typed error state, not a
generic failure, visible in flow-admin's timeline). The LLM never sees any token: credentials reach
MCP servers per-run via the transport factory's process env.

## Recipe 2 — MCP tool server behind audience-scoped tokens

```php
// Orchestrator: mint per tool server
$delegated = app(TokenExchanger::class)->exchange(new TokenExchangeRequest(
    subjectToken: $userToken,
    scopes: ['crm:contacts.read'],
    audience: 'mcp://crm-tools',        // ← the tool server's identity
));
```

```php
// Tool server (a Laravel app with laravel-iam-client): enforce aud + intersection
Route::post('/mcp', McpController::class)->middleware('iam.can.delegated:crm:contacts.read');
```

A token minted for `mcp://billing-tools` is refused at `mcp://crm-tools` before any scope logic:
one stolen token cannot fan out across tool servers. Keep tools **small and bounded**; pin the MCP
spec version in your adapter.

## Recipe 3 — mobile app backend (the MOBILE-SEC-LLM-001 pairing)

The mobile rule says: *the app never holds a provider key; the app calls our backend; actions are
confirmed per-action on screen; the server re-validates*. Delegation is the server half:

1. The app talks only to **your backend orchestrator** (the user's session rides the normal app auth).
2. The orchestrator holds the agent's private key and the user's token, performs the exchange, and
   calls tool APIs with the delegated token — the model, and the app, never see either token.
3. Per-action confirmation on the phone maps to the **consent grant** (and, for sensitive single
   actions, a rebel-step-up purpose with dynamic linking on the action's parameters).
4. Revocation in the app profile calls `DELETE /iam/me/delegations/{grantId}` — one tap.

## Recipe 4 — JIT elevation instead of a flat deny (v1.1)

When an agent hits `invalid_scope` (outside the intersection), don't dead-end: open a **JIT
elevation request** on the grant (`DelegationElevationService::request()` — extra scopes +
reason). The delegating user gets nudged out-of-band (rebel-channels, best-effort), approves
with a step-up re-consent bound to exactly the extra scopes, and the agent re-exchanges with the
widened grant. In flow-ai this maps to pausing the node (approval gate) rather than failing the
run. Full mechanics: [Budget & elevation](/guides/budget-and-elevation).
