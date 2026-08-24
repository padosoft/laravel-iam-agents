---
title: Troubleshooting — the RFC 8693 errors, one by one
description: Every error the token-exchange endpoint emits, what actually caused it, and where to look.
---

# Troubleshooting — RFC 8693 errors, one by one

The exchange endpoint answers with standard OAuth error codes. **By design the client gets the
coarse code and the audit stream gets the detail** — an attacker probing the endpoint learns
nothing about *why*; your admin reads the exact reason in
`GET /api/iam/v1/audit?stream=delegation` (`iam.delegation.exchange.refused`).

## `invalid_client`

The client assertion failed: wrong signature, expired/replayed `jti`, unknown `client_id`, or the
client does not belong to an agent. **Check:** the agent's JWKS pasted at approval matches the
private key in use; the assertion `aud` is the token endpoint URL; clocks are sane.

## `invalid_request` — `actor_token`

> *"Delega multi-hop non abilitata (max_delegation_depth=1)."*

You sent an `actor_token`. Depth is 1 in MVP; the parameter is recognized (wire conformance) and
refused cleanly. Drop it — the agent's identity comes from the client assertion.

## `invalid_request` — `requested_token_type` / `subject_token_type`

Only `urn:ietf:params:oauth:token-type:access_token` is issuable/accepted today. `id_token` as
subject is v2.

## `invalid_request` — `subject_token`

The parameter is missing. The user's access token goes in `subject_token`, the agent's key signs
the *assertion* — the two are different things.

## `invalid_grant`

The coarse bucket for **every** policy refusal — deliberately indistinguishable client-side:

| Actual cause (visible in audit) | Fix |
| --- | --- |
| Agent not `active` (pending/suspended/retired) | Approve/resume the agent |
| Subject token invalid or expired | Re-authenticate the user |
| Subject token without `sid` | Delegation requires a human session — machine tokens can't delegate |
| User's session no longer alive | The user logged out / was revoked: re-login, re-exchange |
| No delegation grant for (user, agent) | The user never consented — send them to the consent flow |
| Grant expired or revoked | Ask for fresh consent (or the revocation was the point) |
| `delegation_budget_unenforceable` — grant has a budget, no `DelegationBudgetGuard` bound | Bind a meter (e.g. laravel-ai-finops `iam_delegation` integration) or grant without a budget. Fail-closed by design: a budget nobody enforces would be a broken promise to the user |
| `delegation_budget_exhausted: <reason>` — the bound meter said no | The grant's budget cap is crossed. The user grants fresh consent with a new budget (or an admin reviews the spend) — the cap doing its job is not an error |

## `invalid_scope`

> *"(intersezione vuota tra scope richiesti, grant e max_scopes agente)"*

The requested scopes ∩ grant scopes ∩ agent `max_scopes` is empty. Request fewer/different scopes,
or ask the user to widen the grant (a **new** consent — dynamic linking makes the wider ask
explicit). Never widen `max_scopes` casually: that ceiling is the org's review boundary.

## Exchange succeeds but the resource server denies

The exchange checks the *agent/grant* half; the PDP checks **both** halves per request. Look at the
delegated decision (the two sub-decision ids in the audit): the **user** layer probably denies —
the user lacks the permission behind the scope. Scopes are the upper bound, permissions are the
truth.

## Consent errors (`422` on the self-service endpoints)

| Error | Meaning |
| --- | --- |
| `consent_unavailable` | The verifier is `Null` (unconfigured), or no live IAM session (check `session_resolver`) |
| `agent_not_active` | Consent can only target an `active` agent |
| `scopes_exceed_agent_ceiling` | Requested scopes outside the agent's `max_scopes` |
| `ttl_exceeds_maximum` | Longer than `grants.max_ttl_days` |
| Binding mismatch on store | Parameters differ between challenge and store calls — send the **exact same four** (five, when a `budget` is included: it is part of the binding too) |

## Elevation errors (`ElevationException` / `422` on the elevation endpoints)

| Error | Meaning |
| --- | --- |
| Grant absent or not active | Elevation only extends a **living** grant — revoked/expired grants need fresh consent, not elevation |
| Scopes already covered | The grant already has them: just re-exchange |
| Scopes outside the agent ceiling | `max_scopes` is structural — no user consent raises it. An admin must widen the ceiling first (that's an org review, on purpose) |
| Request no longer decidable | Pending expired (`elevation.pending_ttl_minutes`, default 15) or already decided. Fail-closed: the agent re-requests |
| Request "not found" for a logged-in user | Elevation requests are only visible to the grant's own user — other users get non-existence, never "not yours" |
