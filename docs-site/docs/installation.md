---
title: Installation
description: Requirements, install steps, configuration surface and versioning policy of laravel-iam-agents.
---

# Installation

## Requirements

| Requirement | Version |
| --- | --- |
| PHP | ^8.3 |
| padosoft/laravel-iam-server | ^1.23 (TokenIssuanceContext, agent app type, webhook push, `/capabilities`) |
| padosoft/laravel-iam-contracts | ^1.3 (the `Delegation\` namespace) |
| league/oauth2-server | ^9.0 |
| padosoft/laravel-rebel-step-up | ^0.2 — *optional*, only for the PSD2-grade consent verifier |

The module is installed **in the same app as the server** (it extends the server's
`AuthorizationServer`, PDP and audit chain — it is not a standalone issuer by design: one control
plane, one JWKS, one audit chain).

## Install

```bash
composer require padosoft/laravel-iam-agents
php artisan migrate
php artisan vendor:publish --tag=iam-agents-config   # optional
```

::: callout note "Not on Packagist yet?"
Until the one-time Packagist submit, add the repo directly:
`composer config repositories.iam-agents '{"type":"git","url":"https://github.com/padosoft/laravel-iam-agents.git"}'`
:::

Migrations create `iam_agents` and `iam_delegation_grants`. The service provider then:

- registers the **RFC 8693 grant** into the server's token endpoint (`app()->extend(AuthorizationServer::class)`);
- decorates the PDP with the **`DelegatedAuthorizationEngine`** implementation;
- mounts the **self-service** routes (`iam/me/delegations`, your app's guard), the **Admin API**
  resources (under the server's admin prefix, same middleware stack) and — only if you enable it —
  the **agentic registration** endpoints;
- declares `agents` on the server's **`GET /capabilities`**.

## Configuration at a glance

Full reference: [Configuration](/reference/config). The two decisions you must make:

1. **The consent verifier** (`iam-agents.consent.verifier`) — `null` (default) refuses every grant
   creation. See [Consent](/guides/consent).
2. **The session resolver** (`iam-agents.consent.session_resolver`) — tells the module where *your*
   app keeps the user's IAM `sid`. Delegation requires a live human session behind it.

Everything else has safe defaults: delegated TTL 300s (hard cap 900 in code), grant max 30 days,
delegation depth 1, registration **off**.

## Versioning

Semver on 0.x: breaking changes bump the minor until 1.0. The wire protocol (RFC 8693 params,
`act`/`pds_dgr` claims, `typ: delegated+jwt`) and the fail-closed invariants are **stable from
0.1.0** and will not loosen — v2 work (multi-hop `act` chains, operator claim) is strictly additive.
