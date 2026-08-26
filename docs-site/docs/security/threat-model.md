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

### An incident in progress (the fleet has to stop, now)

The asymmetric kill switch: **one** admin with `iam:delegations.manage` freezes delegation —
globally, per organization, or for one agent — with immediate effect on both issuance *and*
delegated decisions, so tokens already in circulation stop deciding rather than running out their
five-minute TTL. Lifting requires a quorum of **distinct** admins holding a separate permission,
`iam:delegations.unfreeze`.

The attack this specifically anticipates is the one *against the response*: an attacker (or a
panicking operator) who wants the fleet running again before anyone has understood why it stopped.
Hence the two rules that matter. The quorum is **photographed onto the freeze row** at freeze time,
so lowering it in configuration afterwards changes nothing; and approvals are unique per identity at
the **schema** level, so one admin cannot make a quorum alone by approving repeatedly.

Whoever froze may approve like anyone else — excluding them would remove a signature from the person
handling the incident without stopping anyone, since the attacker who wants to *lift* a freeze is
not the one who *set* it.

Revoking a grant and suspending an agent are never blocked by a freeze: a kill switch that blocks
the incident response it caused is worse than none.

### An agent that lies about what it did

Receipts do not prevent it — nothing can — but they change who carries the cost. A receipt is
minted **only** by the holder of a valid delegated token, and its identities are copied from that
verified token rather than from the request body, so an agent cannot sign for another agent or for
a user who never delegated to it. What it *can* do is sign a false statement about its own
action — and that statement is non-repudiable, which makes it evidence against the agent.

Two refusals close the timing hole. A **revoked or expired grant** cannot mint: otherwise an agent
just cut off could backdate its own history precisely when it most wants to. A **frozen** fleet
cannot mint either: signing is an action.

The issuer's signature attests the identity binding, **not** the truth of the action. Stating that
in the contract is part of the design: a receipt read as proof the order shipped would be worse
than no receipt.

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
| Budgeted grant with no `DelegationBudgetGuard` bound (v1.1) | `invalid_grant` (`delegation_budget_unenforceable`) |
| Budget guard verdict: deny (v1.1) | `invalid_grant` (`delegation_budget_exhausted: <reason>`) |
| Consent confirm with a tampered budget (v1.1) | `ConsentFailedException` (binding mismatch) |
| Elevation for scopes outside the agent `max_scopes` ceiling (v1.1) | refused (`ElevationException`) |
| Elevation approve after `pending` expiry / by a different user (v1.1) | refused fail-closed |
| Exchange while delegation is frozen (v1.3) | `invalid_grant` (audited `delegation_frozen: frz_… (scope)`) |
| Delegated decision while frozen (v1.3) | denied, reason `delegation_frozen` |
| Elevation requested while frozen (v1.3) | refused (`ElevationException`) — a frozen fleet does not widen its own authority |
| The same admin approving a lift twice (v1.3) | counted once; quorum unchanged |
| `lift_quorum` lowered in config after a freeze (v1.3) | ignored — the freeze keeps the quorum it was created with |
| Freeze state unreadable (v1.3) | denied `freeze_state_unavailable` — "I could not check" is not "it is fine" |
| Minting a receipt with no token / a token this issuer did not sign (v1.4) | refused |
| Minting from a **plain user token** (no `act`) (v1.4) | refused — it would make a user sign as an agent |
| Minting on a revoked or expired grant (v1.4) | refused — no backdated history |
| Minting with a suspended agent, or while frozen (v1.4) | refused |
| A token citing a grant belonging to a **different** (user, agent) pair (v1.4) | refused |
| `verify()` handed a delegated access token as "a receipt" (v1.4) | refused (`aud` + `pds_att`) |

## Residual risks, stated honestly

- **Within-TTL staleness**: a revocation takes up to one delegated TTL (≤ 5 min) to reach a resource
  server that skips introspection. Mitigation: introspection-mandatory posture + webhook push of
  revocation events.
- **A too-generous admin**: wide `max_scopes` ceilings are a governance problem; the manifest
  approval workflow and (v2) IGA access reviews are the mitigations — deny-overrides means a
  user-side deny still wins.
- **Host app misconfiguration**: a missing session resolver or a Null verifier fails **closed**
  (nothing works), never open.
- **A quorum larger than the team**: `lift_quorum` set above the number of people actually holding
  `iam:delegations.unfreeze` makes a freeze unliftable. The value is deliberately not clamped to the
  admin count — that count is the host's to know — so it is a configuration review item, not a
  runtime guard.
