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

## Consent

| Key | Default | Notes |
| --- | --- | --- |
| `consent.purpose` | `iam-delegation-grant` | Step-up purpose. **Kebab-case is mandatory**: dots are config path separators in rebel-step-up |
| `consent.required_aal` | `aal2` | NIST 800-63B minimum for the consent evidence — explicit, never implicit. Unknown values fall back to AAL2 (requirements never degrade) |
| `consent.verifier` | `null` | FQCN of the `ConsentVerifier`. `null` = `NullConsentVerifier` — **no grant can be created**. Options: `IamNativeConsentVerifier::class`, `RebelStepUpConsentVerifier::class` (needs `padosoft/laravel-rebel-step-up` ^0.2) |
| `consent.session_resolver` | `null` | FQCN of the `DelegationSessionResolver` — where YOUR app keeps the user's IAM `sid`. `null` = fail-closed (native consent refuses) |

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
