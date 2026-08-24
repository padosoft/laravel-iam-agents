---
title: Introduction
description: Delegated access for AI agents on Laravel IAM — agents as first-class identities acting on behalf of users via RFC 8693 token exchange, with strict-intersection authority, PSD2-grade consent and a tamper-evident audit stream.
---

# laravel-iam-agents

**Delegated access for AI agents** — the optional [laravel-iam-server](https://doc.laravel-iam-server.padosoft.com)
module that lets an AI agent act *on behalf of* a user **without ever holding the user's token**.

## The invariant

Everything in this module enforces one sentence:

> A delegated token carries **two identities** (`sub` = the user, `act` = the agent), and effective
> authority is the **strict intersection** of what the user may do and what the agent may do —
> **never the union**, evaluated fresh by the PDP, **fail-closed**.

```json
{ "iss": "https://iam.example.com", "sub": "user:42",
  "act": { "sub": "agent:01J8XKQ0V2" },
  "aud": "mcp://crm-tools", "scope": "orders:read orders:draft",
  "pds_dgr": "dgr_01J9…", "exp": 1756000300 }
```

## Why not just hand the agent the user's token?

Because then the agent *is* the user: every permission, for the token's whole life, indistinguishable
in every log. If the agent is manipulated (prompt injection is an **input** problem — you cannot prompt
it away), the blast radius is the user's entire account. Delegation shrinks that to: *the scopes the
user consented to* ∩ *the permissions the agent itself has* — for ≤ 5 minutes at a time, revocable
in one click, with both identities in every audit record.

## What the module ships

| Piece | What it does |
| --- | --- |
| **Agent registry** | Agents as first-class subjects (`agent:{ulid}`), lifecycle `pending → active → suspended/retired`, `private_key_jwt` only |
| **Delegation grants** | The user's consent: agent, scopes, purpose, expiry, consent evidence (AAL + confirmation id), revocable |
| **RFC 8693 grant** | Token exchange on the server's own `/oauth/token` — registered from the outside, no core fork |
| **Intersection PDP** | `checkDelegated()` decorator: user check ∧ agent check ∧ grant still active, deny-overrides |
| **PSD2-grade consent** | Step-up bound to *(agent, scopes, ttl, purpose)* — parameters changed after the screen ⇒ refused |
| **Gated agentic registration** | RFC 7591 DCR + `auth.md`/ID-JAG discovery — always lands `pending`, human approves |
| **Audit `stream=delegation`** | Every exchange (issued *and* refused), grant create/revoke, lifecycle transition — sealed in the server's hash chain and pushed to webhooks |

## Where to go next

- **New to delegation?** Read the [Glossary](/concepts/glossary) — five terms, concrete examples.
- **Want it running?** The [Quickstart](/quickstart) goes from `composer require` to a delegated
  call in five minutes.
- **Reviewing security?** [Threat model & negative tests](/security/threat-model) — what we refuse,
  proven by tests.
- **Something failing?** [Troubleshooting](/reference/troubleshooting) explains every RFC 8693 error
  this server emits, one by one.
