---
title: "The asymmetric kill switch"
description: "One admin stops the fleet instantly; restarting it needs a quorum of distinct admins. Why the two sides are deliberately unequal, and what the freeze does and does not block."
---

# The asymmetric kill switch

Something is wrong. An agent is calling a tool it has never called, a detector is
firing, a customer is on the phone. The question is not *"who else should agree
that we stop?"* — it is **how fast can this stop.**

So: **one admin freezes delegation, immediately, alone.** No approval, no second
signature, no waiting for a colleague at three in the morning.

Restarting is the opposite operation. It is exactly the moment when an attacker —
or an operator who mostly wants the alarm to go away — has an interest in being the
only decision-maker. That is the side that gets the friction.

```
freeze   →  1 admin,  iam:delegations.manage
lift     →  N distinct admins, iam:delegations.unfreeze
```

Two independent axes, not one. The quorum is the obvious half; the **separate
permission** is the half people forget. `iam:delegations.unfreeze` is granted to
fewer people than `iam:delegations.manage`, so "who can stop the fleet" and "who
can restart it" are different lists even before anyone counts signatures.

## Freezing

```http
POST /api/iam/v1/delegation-freezes
{ "scope": "global", "reason": "Anomalous tool calls from agt_01J…" }
```

`reason` is required. A kill switch with no reason is a kill switch nobody knows
when to remove — three days later someone finds a frozen fleet and has to guess.

Three scopes, because in an incident the real question is *how much* to switch off:

| scope | stops |
|---|---|
| `global` | all delegation, everywhere |
| `organization` + `scope_id` | every agent of one organization |
| `agent` + `scope_id` | one agent |

Pressing the button twice during an incident is a normal reflex, so a second
freeze of the same scope returns the first one rather than creating a second
thing to unlock.

## What a freeze actually stops

| | |
|---|---|
| Token exchange | **refused** — no delegated token is issued |
| Delegated decisions (`checkDelegated`) | **denied** — tokens already in circulation stop deciding |
| JIT scope elevation | **refused** — a frozen fleet does not widen its own authority |
| Revoking a grant, suspending an agent | **allowed, always** |

The second row is what makes this a kill switch rather than a pause on new
issuance. Delegated tokens live at most five minutes, but "at most five minutes of
a frozen fleet still acting" is not what anyone means by *stop*.

The last row is a rule, not an oversight: if freezing also blocked revocation, the
kill switch would block the incident response that caused it.

## Lifting

```http
POST /api/iam/v1/delegation-freezes/frz_01J…/approve-lift
{ "note": "Root cause found and patched, see INC-412" }
```

Each call records **one** approval and answers with how many are still missing:

```json
{ "lifted": false, "approvals": 1, "required_quorum": 2, "remaining_approvals": 1 }
```

When the last one lands, the freeze lifts inside the same transaction and
delegation resumes.

## Three decisions worth knowing

**The quorum is photographed at freeze time.** `required_quorum` is written onto
the freeze row when it is created and never re-read from config afterwards. If it
were re-read at lift time, anyone who can edit configuration would set it to `1`
and unfreeze alone — and a control that the person you are defending against can
turn off is not a control.

**Whoever froze may approve, like anyone else.** Excluding them adds no security:
the attacker who wants to *lift* a freeze is not the person who *set* it. It only
removes a signature from the one person actually handling the incident. Two-person
control comes from `lift_quorum >= 2`, not from exclusion. What is enforced — at
the schema level, with a unique constraint, not just in code — is that the
approvals come from **distinct** identities.

**The check is not cached.** A kill switch that takes thirty seconds to kill is not
a kill switch. It costs one indexed lookup on a tiny table per delegated decision,
which is cheaper than the two PDP checks it precedes.

## Configuration

```php
'kill_switch' => [
    'lift_quorum' => env('IAM_AGENTS_FREEZE_LIFT_QUORUM', 2),
],
```

`1` is allowed and means "no quorum" — the permission asymmetry still applies. It
is not the default, because the default should be the control and not the
convenience. Do not set a quorum larger than the number of people who actually
hold `iam:delegations.unfreeze`, or the fleet cannot be restarted at all.

## When the state cannot be read

If the freeze table exists but cannot be queried, every delegated action is denied
with `freeze_state_unavailable`. For a kill switch, *"I could not check"* is not
*"it is fine"*.

The one case treated differently is a **table that does not exist yet** — the
minutes between deploying this version and running `php artisan migrate`. That is
"not installed", not "unreadable", and it does not deny anything. Run the migration.

## Audit

Everything lands in the `delegation` stream, on the server's tamper-evident hash
chain:

| event | risk |
|---|---|
| `iam.delegation.freeze.applied` | high |
| `iam.delegation.freeze.lift_approved` | medium — recorded for **every** approval, including duplicates |
| `iam.delegation.freeze.lifted` | high |

Every approval is audited, not only the one that completed the quorum: *"who wanted
the agents running again"* is a question you answer with the full list, not with
the name of whoever happened to sign last.

Refused exchanges carry `delegation_frozen: frz_… (global)` as their refusal
reason. The client never learns why — a refusal must not explain to an agent that
it has been stopped.
