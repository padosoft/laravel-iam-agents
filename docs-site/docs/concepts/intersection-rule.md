---
title: The intersection rule
description: Effective authority = user ∩ agent ∩ grant — never the union, deny-overrides on every layer, evaluated fresh, fail-closed.
---

# The intersection rule

## The rule

```
effective authority = what the USER may do
                    ∩ what the AGENT may do
                    ∩ what the GRANT covers (and the grant is still Active)
```

Never the union. Evaluated **fresh by the PDP on every check** — the token's scopes are an upper
bound, not the decision.

## Why intersection and not union

The union would mean an agent *adds* authority to a user (privilege escalation by delegation), or a
user *lends* authority the agent's operators never reviewed. Both are the **confused deputy**
problem wearing different hats. The intersection means a compromised prompt can, at absolute worst,
do only what *both* the human consented to *and* the agent was structurally allowed — for the token's
few remaining minutes.

## The two layers are real PDP subjects

Agents are ordinary PDP subjects (`agent:{ulid}`) with their own roles/permissions. That is what
makes the intersection *computable with the existing engine*: `checkDelegated` runs the normal
`check()` **twice** — once for the user, once for the agent — then verifies the cited grant:

```php
$decision = app(DelegatedAuthorizationEngine::class)->checkDelegated(
    new SubjectRef('user', '42'),
    new DelegationChain(ActorRef::fromAgentId('01J8XKQ0V2')),
    ['action' => 'shop:orders.read', 'delegation_grant_id' => 'dgr_01J9…'],
);
```

The decision cites **both sub-decision ids**, so an auditor can replay separately *why the user side
allowed* and *why the agent side allowed*.

## Deny-overrides, composed

| Situation | Outcome |
| --- | --- |
| User allowed ∧ agent allowed ∧ grant Active | **allow** |
| User denied (anything) | **deny** — the agent's permissions are irrelevant |
| Agent unknown / `pending` / `suspended` / `retired` | **deny** — only `active` delegates |
| Grant revoked / expired / for a different pair | **deny**, reason `delegation_grant_not_active` |
| No `DelegatedAuthorizationEngine` bound (module absent) | **deny** — a delegated request never falls back to a single-subject check |

That last row matters: fail-closed applies to the *plumbing*, not just the data. A resource server
receiving an `act` claim without delegated-check capability refuses — it does not "helpfully" check
just the user.

## Scopes vs permissions

At **exchange time** the server intersects `requested scopes ∩ grant scopes ∩ agent max_scopes`
(empty ⇒ `invalid_scope`). The **user layer** is not projected into scopes: it is enforced
per-request by `checkDelegated`. Token = upper bound; PDP = truth. This is deliberate — a scope
projection would freeze the user's permissions at exchange time, and a permission removed mid-token
would keep working until expiry.
