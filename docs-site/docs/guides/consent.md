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
