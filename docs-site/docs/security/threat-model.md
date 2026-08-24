---
title: Threat model & negative tests
description: What the module refuses by design — confused deputy, prompt injection blast radius, registration spam — and the negative tests that prove it.
---

# Threat model & negative tests

Security here is **proven by tests, not promised in prose**: every refusal below is pinned by a test
in the suite (`tests/Feature/`, `tests/Rebel/`), and the same negative scenarios are the acceptance
contract for consumers.

## Threats and how the design answers

### Confused deputy (the agent is tricked into misusing its authority)

The classic failure: software with broad standing authority performs a low-privilege user's request
with high-privilege effect. Here the agent **has no standing user authority** — only its own
permissions, usable exclusively *through* a delegated token whose `sub` is the requesting user.
The intersection means the deputy can never exceed the *narrower* of the two identities.

### Prompt injection (the model is told to do something else)

Injection is an input problem — it cannot be prompted away. The design bounds the blast radius
instead: the LLM **never holds any token** (the orchestrator does), the token it acts through is
scope-limited, audience-limited and minutes-lived, and every action lands in the audit stream with
both identities. A hijacked agent can, at worst, do what the user consented to, where the token's
`aud` points, for ≤ 5 minutes.

### Stolen delegated token

TTL ≤ 300 s, non-refreshable, audience-scoped, and introspection-mandatory: a replayed token dies
at expiry, cannot be renewed, is refused at any other audience, and dies **immediately** when the
grant is revoked or the user logs out.

### Token-degradation attacks (delegated → full user authority)

A malformed `act` claim **throws** during parsing — `DelegationChain::fromTokenClaims` never
degrades a delegated token into a plain user token. A resource server without delegated-check
capability **denies** delegated requests rather than falling back to a single-subject check.

### Registration spam / operator squatting

DCR and auth.md registrations are rate-limited and land `pending` with zero capabilities. A
pending agent cannot exchange, cannot be consented to, cannot hold scopes.

### Consent tampering (approve X, bind Y)

Dynamic linking: the confirmation is bound to the canonical hash of *(agent, scopes, ttl, purpose)*.
Any parameter changed after the consent screen ⇒ binding mismatch ⇒ refused. The confirmation is
one-shot (UNIQUE `consent_confirmation_id`).

## The negative-test contract

These must stay red-line tests in every consumer integration too:

| Scenario | Expected |
| --- | --- |
| Exchange without a delegation grant | `invalid_grant` |
| Exchange after grant revocation | `invalid_grant` |
| Exchange with agent `pending`/`suspended`/`retired` | `invalid_grant` |
| Exchange with the user's session dead / subject token without `sid` | `invalid_grant` |
| Requested scopes outside `grant ∩ max_scopes` | `invalid_scope` |
| `actor_token` presented (depth 1) | `invalid_request` |
| Delegated token at a pre-act PEP / without delegated engine | request denied |
| Single-subject check with `act` present | refused by the PDP path |
| Consent confirm with tampered parameters | `ConsentFailedException` (binding mismatch) |
| Same confirmation used for a second grant | refused (UNIQUE) |
| Achieved consent AAL below the configured minimum | refused fail-closed |

## Residual risks, stated honestly

- **Within-TTL staleness**: a revocation takes up to one delegated TTL (≤ 5 min) to reach a resource
  server that skips introspection. Mitigation: introspection-mandatory posture + webhook push of
  revocation events.
- **A too-generous admin**: wide `max_scopes` ceilings are a governance problem; the manifest
  approval workflow and (v2) IGA access reviews are the mitigations — deny-overrides means a
  user-side deny still wins.
- **Host app misconfiguration**: a missing session resolver or a Null verifier fails **closed**
  (nothing works), never open.
