---
title: Audit stream & endpoints
description: The delegation audit events, the Admin API resources, the self-service routes and the discovery endpoints — in one reference table.
---

# Audit stream & endpoints

## Audit — `stream=delegation`

Every event is sealed in the server's tamper-evident hash chain and pushed to matching webhook
subscriptions (server ≥ 1.23 revocation push). Event types:

| Event | When |
| --- | --- |
| `iam.delegation.agent.registered` | Agent created (admin, DCR, or auth.md path) |
| `iam.delegation.agent.{approved\|suspended\|resumed\|retired\|rejected}` | Lifecycle transitions, with the acting admin |
| `iam.delegation.grant.created` | Consent verified, grant stored — cites `grant_id`, scopes, purpose, `consent_aal`, `*_confirmation_id` |
| `iam.delegation.grant.revoked` | By the user or an admin — cites who |
| `iam.delegation.exchange.issued` | Successful RFC 8693 exchange — user, agent, scopes, `grant_id` |
| `iam.delegation.exchange.refused` | Refused exchange **with the detailed reason** (the client only gets the RFC error; the *why* lives here) |

::: callout warning "Metadata naming rule" icon:key
Audit metadata never uses keys containing the substring `token` — the server's admin APIs redact by
substring. Use `grant_id`, `consent_confirmation_id`. This is why the claim is `pds_dgr`, not
`*_token_id`.
:::

Query it like any server audit: `GET /api/iam/v1/audit?stream=delegation` — or the **Delegation
audit** page in [laravel-iam-console ≥ 1.2](https://github.com/padosoft/laravel-iam-console).

## Admin API (server admin prefix, e.g. `/api/iam/v1`)

Same middleware stack as the server (`iam.admin_auth` / `iam.can` / `iam.idempotency`). Permission
slugs: `iam:agents.manage`, `iam:delegations.manage`, `iam:decisions.check`.

| Route | Does |
| --- | --- |
| `GET/POST /agents` · `GET /agents/{id}` | List/create/inspect agents (filters: `status`, `operator`) |
| `POST /agents/{id}/approve` | **The human gate**: pastes public JWKS, creates the OAuth client (confidential, `private_key_jwt`, token-exchange only), activates |
| `POST /agents/{id}/suspend` · `/retire` | Kill-switch / terminal retirement |
| `GET /delegation-grants` | Org-wide grant search |
| `POST /delegation-grants/{id}/revoke` | Admin revocation |
| `POST /decisions/check-delegated` | The intersection decision endpoint for remote PEPs |

## Self-service (`iam/me/delegations`, host-app guard)

| Route | Does |
| --- | --- |
| `GET /` | "My delegations": agent, scopes, purpose, status, expiry, consent AAL |
| `POST /consent-challenge` | Step 1: open the bound consent challenge |
| `POST /` | Step 2: verify + create the grant (one-shot confirmation) |
| `DELETE /{grantId}` | One-click revoke — **no step-up, ever** |

## Discovery (public when the module is enabled)

| Route | Does |
| --- | --- |
| `GET /.well-known/agent-auth.json` | The `agent_auth` block (auth.md interop: identity endpoint, ID-JAG support, events endpoint) |
| `GET /AUTH.md` | The procedural recipe file for agent onboarding |
| `GET /capabilities` (server core) | Lists `agents` when the module is enabled — consoles gate their UI on this, no 409-probing |
