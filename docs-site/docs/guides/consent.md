---
title: Consent — the three verifiers
description: NullConsentVerifier (fail-closed default), IamNativeConsentVerifier, and the PSD2-grade RebelStepUpConsentVerifier — dynamic linking of (agent, scopes, ttl, purpose), one-shot consumption.
---

# Consent — the three verifiers

Creating a delegation grant is a **sensitive action**: it hands part of a human's authority to a
piece of software. The module treats it like PSD2 treats a payment — step-up confirmation **bound to
the exact parameters** being approved.

## The flow (identical for every verifier)

1. `POST /iam/me/delegations/consent-challenge` with `agent_id`, `scopes`, `ttl_seconds`, `purpose`
   → the verifier opens a challenge **bound** to those parameters and returns
   `{challenge_id, method, expires_at}`.
2. The user completes the challenge (e.g. types the OTP).
3. `POST /iam/me/delegations` with the **same parameters** + `challenge_id` + `verification`
   → the verifier confirms, the grant is created citing the evidence
   (`consent_confirmation_id`, `consent_aal`).

**Dynamic linking:** if *any* parameter differs between step 1 and step 3 — one more scope, a longer
TTL — the binding hash diverges and the confirmation is **refused**. The user approved *that*
delegation, not a similar one.

**Budget joins the binding (v1.1):** an optional `budget` object (`amount`/`currency`/`tokens`/
`calls`) on both calls is the fifth bound parameter — the user approves the *intensity* together
with the authority, and a budget changed after the challenge invalidates the confirmation like any
other tampered parameter. See [Budget & elevation](/guides/budget-and-elevation).

**One-shot:** `iam_delegation_grants.consent_confirmation_id` is UNIQUE — the same confirmation can
never create two grants, even under concurrency.

## Choose your verifier (`iam-agents.consent.verifier`)

### `NullConsentVerifier` — the default

Refuses everything. An installed-but-unconfigured module can create **zero** grants. This is not a
placeholder; it is the fail-closed posture applied to configuration.

### `IamNativeConsentVerifier`

Uses the IAM server's **native step-up** (`StepUpProvider`): a real single-use claim
(`consumed_at`), no extra packages. The parameter binding is emulated module-side (canonical hash
cached at challenge time, re-checked at confirmation). Requires a live IAM session — configure
`consent.session_resolver` so the module can find the user's `sid`.

**Pick when:** you want zero extra dependencies and the server's own step-up factors are enough.

### `RebelStepUpConsentVerifier`

Uses [`padosoft/laravel-rebel-step-up` ≥ 0.2](https://github.com/padosoft/laravel-rebel-step-up):
the *(agent, scopes, ttl, purpose)* tuple is bound through rebel's `GenericBindingContext` — the
keyed hash lives on the challenge row and `confirm()` re-verifies it **driver-side**
(`binding_mismatch`). This is real PSD2-style dynamic linking, not emulation, with rebel's
multi-channel drivers (email OTP, and any driver you register). Evidence is read via
`RebelStepUp::confirmation()` and must reference exactly the confirmed challenge; an unknown or
insufficient achieved AAL is refused fail-closed against `iam-agents.consent.required_aal`.

```php
// config/iam-agents.php
'consent' => ['verifier' => \Padosoft\Iam\Agents\Consent\RebelStepUpConsentVerifier::class],

// config/rebel-step-up.php — the purpose MUST exist, kebab-case, with SCA on:
'purposes' => [
    'iam-delegation-grant' => [
        'required_assurance' => 'aal2',
        'drivers' => ['email-otp'],
        'always_require' => true,
        'sca' => ['dynamic_linking' => true],
    ],
],
```

**Pick when:** you want bank-grade consent UX (multi-channel, funnel analytics in rebel-admin) or
compliance asks for genuine dynamic linking.

## Rules that hold regardless of verifier

- **AAL2 minimum by default** (`consent.required_aal`), explicit — never inferred.
- The consent screen shows: agent name + owner, scopes **in human language** (from the manifest
  descriptions), purpose, duration, and *"revocable at any time"*.
- **Revoking never requires step-up.** Granting is hard; ungranting is one click. Any design where
  revocation is harder than consent is a dark pattern and a security bug.

## Preview: what the delegation actually covers

A consent screen that says `orders:read` asks the user to approve a **name**, not
an effect. Nobody knows which orders those are — and "how many" is exactly the
question that decides whether the delegation is small or enormous.

`POST /me/delegations/consent-preview` answers it before the challenge:

```json
{ "agent_id": "agt_01J8…", "relations": ["owner", "editor"] }
```

```json
{ "data": {
  "agent_status": "active",
  "relations": [
    { "relation": "owner", "resources": ["order:1042", "order:1043"], "total": 2, "truncated": false }
  ]
} }
```

It runs the PDP's reverse index (`listResources`) over **both** subjects and
returns the **intersection** — the same invariant the PDP enforces, so the preview
cannot promise access the decision would refuse.

Three behaviours that are part of the contract, not decoration:

- **Truncation is declared.** `total` and `truncated` always come back. A user
  with ten thousand orders cannot see them all, but showing ten without saying
  there are 9,990 more makes a huge delegation look small — worse than showing
  nothing. Tune with `iam-agents.consent.preview_limit` (default 25).
- **An empty intersection is the useful answer.** Granting would give access to
  nothing; the user should learn that *before* consenting.
- **A non-active agent returns no resources.** Listing them next to a suspended
  agent would suggest an access that would not happen anyway.

::: callout warning "The preview is not an authorization" icon:triangle-alert
It is a snapshot taken now; the PDP at request time remains the truth. If
permissions change between preview and use, the PDP decides — not this list.
:::
