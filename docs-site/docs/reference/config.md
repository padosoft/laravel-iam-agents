---
title: Configuration
description: Every key of config/iam-agents.php, with defaults and the fail-closed rationale.
---

# Configuration

`php artisan vendor:publish --tag=iam-agents-config` → `config/iam-agents.php`. Every default is
fail-closed: the module installed but not configured concedes nothing.

## Module switch

| Key | Default | Notes |
| --- | --- | --- |
| `enabled` | `env('IAM_AGENTS_ENABLED', true)` | The server can also gate it via `config('iam.agents.enabled')` (config-flag + 409 pattern) |

## Tokens

| Key | Default | Notes |
| --- | --- | --- |
| `tokens.delegated_ttl` | `300` (s) | **Hard cap 900 enforced in code** — config cannot raise it past 15 min. Short by design: the re-exchange is the revocation freshness check |
| `tokens.typ` | `delegated+jwt` | The dedicated JOSE `typ` header. Hygiene; introspection is the defence |

## Grants

| Key | Default | Notes |
| --- | --- | --- |
| `grants.max_ttl_days` | `30` | Ceiling on a delegation grant's lifetime — consent is never eternal |
| `max_delegation_depth` | `1` | MVP: `actor_token` refused with a clean `invalid_request` (wire-conformant, v2-ready) |

A grant's optional **budget** is per-grant data (part of the consent), not configuration.
Enforcement is a container binding: bind a `DelegationBudgetGuard` (e.g. the laravel-ai-finops
meter) — a budgeted grant with no guard bound is refused at exchange, fail-closed. See
[Budget & elevation](/guides/budget-and-elevation).

## Consent

| Key | Default | Notes |
| --- | --- | --- |
| `consent.purpose` | `iam-delegation-grant` | Step-up purpose. **Kebab-case is mandatory**: dots are config path separators in rebel-step-up |
| `consent.required_aal` | `aal2` | NIST 800-63B minimum for the consent evidence — explicit, never implicit. Unknown values fall back to AAL2 (requirements never degrade) |
| `consent.verifier` | `null` | FQCN of the `ConsentVerifier`. `null` = `NullConsentVerifier` — **no grant can be created**. Options: `IamNativeConsentVerifier::class`, `RebelStepUpConsentVerifier::class` (needs `padosoft/laravel-rebel-step-up` ^0.2) |
| `consent.session_resolver` | `null` | FQCN of the `DelegationSessionResolver` — where YOUR app keeps the user's IAM `sid`. `null` = fail-closed (native consent refuses) |

## Elevation (JIT scope elevation, v1.1)

| Key | Default | Notes |
| --- | --- | --- |
| `elevation.pending_ttl_minutes` | `env('IAM_AGENTS_ELEVATION_PENDING_TTL', 15)` | A pending elevation request expires on its own — an ignored request never elevates (fail-closed) |
| `elevation.purpose` | `iam-delegation-elevation` | Step-up purpose of the **re-consent** that approves an elevation (the request's reason is appended). Kebab-case, same rule as `consent.purpose` |
| `elevation.notifier` | `null` | FQCN of the `ElevationNotifier` for the out-of-band nudge (e.g. [rebel-channels](https://github.com/padosoft/laravel-rebel-channels)). `null` = no notification; requests are still visible and decidable in self-service. Delivery is best-effort and audited — never authoritative |

## Kill switch (asymmetric, v1.3)

| Key | Default | Notes |
| --- | --- | --- |
| `kill_switch.lift_quorum` | `2` | Distinct admins required to lift a freeze. Freezing always takes exactly one. |

The value is **photographed onto the freeze row** when the freeze is created and never
re-read here at lift time — otherwise anyone able to edit this file would set it to `1`
and unfreeze alone.

`1` is allowed and means "no quorum"; the permission asymmetry
(`iam:delegations.manage` to freeze, `iam:delegations.unfreeze` to approve a lift) still
applies. Do not set a quorum larger than the number of people who actually hold
`iam:delegations.unfreeze`, or the fleet cannot be restarted.

## Action receipts (v1.4)

| Key | Default | Notes |
| --- | --- | --- |
| `receipts.enabled` | `true` | On by default: minting still requires a valid delegated token and a live grant, so the surface does not exist until a delegation does. |
| `receipts.rate_limit` | `120,1` | Throttle on the minting endpoint. Signing is cheap; an agent in a loop must not be able to fill the evidence table. |
| `receipts.ttl_seconds` | `315360000` (10y) | The JWS `exp`. Evidence does not expire, but the `TokenSigner` contract requires an expiry, so it is set far out and stays a formality. What actually bounds external verification is **key rotation** — archive your historical JWKS if you need decade-scale third-party verification; the digest sealed in the audit chain stays probative regardless. |

## Registration

| Key | Default | Notes |
| --- | --- | --- |
| `registration.enabled` | `false` | DCR RFC 7591 + auth.md/ID-JAG endpoints. Registrations always land `pending` — active only via human approval |
| `registration.rate_limit` | `'10,1'` | Laravel throttle string on `POST /oauth/register` |

## Self-service

| Key | Default | Notes |
| --- | --- | --- |
| `self_service.middleware` | `['web', 'auth']` | The guard protecting `iam/me/delegations` — it's the host app's session, not IAM's |
| `run_migrations` | `true` | Set `false` to manage migrations yourself |
