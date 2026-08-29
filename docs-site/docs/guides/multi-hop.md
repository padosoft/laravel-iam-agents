---
title: "Multi-hop delegation chains"
description: "An agent delegating to another agent, with the intersection holding on every hop. Why the chain can only narrow authority, why the root grant governs all of it, and why actor_token is still refused."
---

# Multi-hop delegation chains

A single hop is *user → agent*. A chain is *user → A → B*: agent A, already acting
for the user, hands the work to agent B.

Off by default. `max_delegation_depth` is `1`, which refuses a `subject_token`
that already carries `act`. Set it to `2` or more to allow chaining.

## Why it is safe, and where the risk actually is

Adding a hop can only **narrow** authority. The PDP evaluates the strict
intersection over the user *and every actor*, so:

```
effective = user ∩ A ∩ B ∩ …
```

B can never reach something A could not. There is no arrangement of a chain that
yields more authority than the shortest link allows.

The real cost is **accountability**, not authority: whoever authorised B is A, not
the user. The user consented to A. That is why the default is 1 — the mechanism is
correct by construction, but the governance question is one an installation should
answer deliberately rather than inherit.

## The bug this had to avoid

Checking only the *current* actor would have made delegation a way to **gain**
authority. With a chain A→B, if the PDP asked only about B, an action A cannot
perform would go through as soon as A handed it to B. Every actor is queried, and
every actor must allow.

The same reasoning applies to the kill switch: freezing a mid-chain agent stops
the chain. If the freeze looked only at the last actor, it would be bypassable by
adding a hop.

## The root grant governs the whole chain

Authority descends from the consent the user gave the **innermost** agent — the
first one delegated to. Downstream hops have no grant of their own and need none.

The consequence matters operationally: **revoking the root grant stops the entire
chain**, not just the last link. There is one thing to revoke, not N.

## The claim on the wire

The current actor is outermost, per RFC 8693 §4.1:

```json
{
  "sub": "user:42",
  "act": { "sub": "agent:B", "act": { "sub": "agent:A" } },
  "pds_dgr": "dgr_01J9…",
  "sid": "sess_…"
}
```

`sid` travels with the delegated token on purpose: every hop re-verifies that the
human's session is still alive. Without it the second hop would have no way to
notice a logout, and the chain would lose its revocation hook exactly where it
gets longer.

## What is refused

| Refusal | Why |
|---|---|
| `subject_token_already_delegated` | Depth is 1 — chaining is off |
| `max_delegation_depth_exceeded` | The chain is longer than configured |
| `delegation_chain_cycle` | A→B→A adds no accountability and hides a delegation loop as a legitimate chain |
| `invalid_scope` | Nothing survived intersecting **every** hop's `max_scopes` — an agent cannot obtain by delegation a scope its own ceiling denies |
| `invalid_request` on `actor_token` | Refused **even with multi-hop on**: the acting party is already identified by client authentication, and RFC 8693 §2.1 allows omitting it precisely then. Accepting it would mean two sources for the actor's identity, one of them unauthenticated |

## Reading a delegated decision

`checkDelegated()` returns one sub-decision id **per hop**:

```php
'sub_decisions' => [
    'subject' => 'dec_…',              // the user layer
    'actor'   => 'dec_…',              // the current actor (unchanged for single-hop consumers)
    'actors'  => ['agent:B' => 'dec_…', 'agent:A' => 'dec_…'],
],
```

Because one denying layer denies everything, the useful question is *which*
one — each id replays on its own. The console's decision playground renders
exactly this, one row per layer.

## Configuration

```php
// config/iam-agents.php
'max_delegation_depth' => 2,
```

Requires `padosoft/laravel-iam-server` ≥ 1.26 (the delegated token carries `sid`
forward through `TokenIssuanceContext::setSessionId()`).
