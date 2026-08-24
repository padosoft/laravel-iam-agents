---
title: Agentic registration (DCR + auth.md)
description: RFC 7591 Dynamic Client Registration and auth.md/ID-JAG interop — gated, rate-limited, always pending until a human approves.
---

# Agentic registration

Two ways an agent enters the registry. Both are **off by default**, and both converge on the same
rule: **every registration lands in status `pending` with zero grants and zero scopes** — an agent
becomes `active` only when a human approves it in the console/Admin API. There is no
auto-provisioning path, and there never will be.

## Path A — admin creates the agent (always available)

```bash
POST /api/iam/v1/agents             {"name": "Order Copilot", "max_scopes": ["orders:read"]}
POST /api/iam/v1/agents/{id}/approve {"jwks": {"keys": [ …the agent's PUBLIC keys… ]}}
```

Approval is the human gate and does three things atomically: pastes the agent's **public JWKS**,
creates the OAuth client (**confidential**, `private_key_jwt`, **token-exchange grant only** — no
auth-code because agents don't log in interactively, no refresh because delegated tokens are
re-exchanged), and flips the status to `active`.

## Path B — the agent registers itself (opt-in)

Enable with `IAM_AGENTS_REGISTRATION_ENABLED=true`. Two protocols, one landing state:

### RFC 7591 DCR

`POST /oauth/register` (rate-limited, default `10,1`) with standard DCR metadata. The response is a
wire-conformant DCR answer, but the created record is `pending`: no grants, no scopes, unusable
until approved.

### `auth.md` / ID-JAG interop

The module extends discovery for the emerging agent-registration protocol:

- `GET /.well-known/agent-auth.json` — the `agent_auth` block (identity endpoint, supported
  identity types incl. `urn:ietf:params:oauth:token-type:id-jag`, events endpoint);
- `GET /AUTH.md` — the human/agent-readable recipe file.

An ID-JAG assertion presented at the identity endpoint creates — again — a **`pending`**
registration. Same approval gate, same audit trail.

## Why "pending forever until a human clicks"

Open registration endpoints get spammed, squatted, and probed. The design accepts that and makes it
harmless: a pending registration can do *nothing* — it cannot exchange, cannot hold scopes, cannot
appear in a consent screen. The cost of a thousand junk registrations is a list an admin bulk-rejects;
the cost of one auto-approved agent would be an authorization bypass. Registration/approval/rejection
are all audited (`iam.delegation.agent.registered`, `.approved`, …) on the `delegation` stream.

## Lifecycle

```
pending → active → suspended ⇄ active
                 → retired (terminal)
```

`suspended`/`retired` agents fail **both** at exchange (step 1 of the pipeline) and at
`checkDelegated` (agent layer) — suspension is an instant, org-wide kill-switch that leaves every
grant intact for a later un-suspend.
