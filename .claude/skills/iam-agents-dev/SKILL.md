---
name: iam-agents-dev
description: Use when adding or changing code in padosoft/laravel-iam-agents — encodes the delegation invariants (strict intersection, fail-closed, TTL cap, no auto-provisioning), the TDD gates, and the branch→PR→CI→release Definition of Done.
---

# Developing laravel-iam-agents

You are extending the **delegated-access module** of the Laravel IAM ecosystem. The module's job is
to let AI agents act on behalf of users *without ever holding their tokens*. Read `CLAUDE.md` at the
repo root first; this skill is the enforcement checklist.

## The invariant (violating it = the PR is wrong, whatever the tests say)

A delegated token carries TWO identities (`sub` = user, `act` = agent); every decision is the
**STRICT INTERSECTION** user ∩ agent ∩ grant — never the union — evaluated fresh, **fail-closed**.

Non-negotiable corollaries — check EVERY diff against these:

1. **Never** hand a user token to an agent, an LLM, a log, or a flow input. The exchange (RFC 8693)
   is the only path, and the orchestrator holds the tokens.
2. **TTL cap**: `TokenExchangeGrant::MAX_DELEGATED_TTL` (900 s) is a code constant, not config.
   Never make it configurable upward; never add a refresh token for delegated tokens — the
   re-exchange IS the revocation freshness check.
3. **Only `active` delegates**: any check that touches agents/grants must deny for
   pending/suspended/retired agents, non-Active grants, dead sessions, and subject tokens without
   `sid`. A new code path that "skips" one of these checks is a vulnerability, not a simplification.
4. **No auto-provisioning, ever**: DCR/auth.md registrations land `pending` with zero grants/scopes.
   `active` requires the human approval endpoint. Agents authenticate ONLY via `private_key_jwt`.
5. **Consent evidence**: challenges are bound to the canonical hash of (agent, scopes, ttl,
   purpose); `consent_confirmation_id` stays UNIQUE (one-shot); revocation NEVER requires step-up.
6. **Audit everything** on `stream=delegation` — refused exchanges included (detail goes to audit,
   the client gets only the RFC error code). Metadata keys must NEVER contain the substring
   `token` (admin APIs redact by substring): use `grant_id`, `consent_confirmation_id`.
7. **Malformed `act` throws** — never degrade a delegated token into a plain user token. Delegated
   tokens are introspection-mandatory; `typ: delegated+jwt` is hygiene, never the defence.
8. **Add, don't mutate**: never add methods to existing contracts interfaces (major bump). New
   capability = new interface (`DelegatedAuthorizationEngine` precedent). The PDP decorator must
   never alter single-subject `check()` behavior.
9. **Fail-closed configuration**: a `null`/missing verifier, resolver or engine binding must refuse,
   never fall back to something more permissive.

## The loop (per sub-task)

1. **Negative test first** (Pest + Testbench): the refusal path is the feature. Then the happy path.
   Suites: `tests/Feature/` (module + server), `tests/Rebel/` (boots the rebel providers too —
   put rebel-adapter tests there, its `RebelTestCase` loads the vendor migrations).
2. Implement: `declare(strict_types=1)`, `final` classes, constructor promotion, Italian docblocks
   (house style of this repo) that say *why*, not *what*.
3. Gates, all green before commit: `vendor/bin/pest` · `vendor/bin/pint --test` ·
   `vendor/bin/phpstan analyse --memory-limit=1G` (**level max** — fix causes, never suppress:
   no `@phpstan-ignore`, no baseline, no cast-to-silence).

## Definition of Done

- One feature branch → one PR to `main`, conventional-commit title; CI (`tests.yml`, PHP
  8.3/8.4/8.5) green before merge; squash-merge keeping the `(#N)` suffix.
- New behavior documented: README (feature table / FAQ if user-facing), `docs-site/docs/` (the
  matching guide/reference page), and `CLAUDE.md` if an invariant or architecture piece changed.
- Release via the `release` workflow (workflow_dispatch, input `version: vX.Y.Z`) — never push tags
  directly.
- If the change touches wire behavior (grant params, claims, errors): update the negative-test
  contract table in `docs-site/docs/security/threat-model.md` and keep RFC conformance (recognize
  parameters you refuse; refuse them cleanly).
