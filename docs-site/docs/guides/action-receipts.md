---
title: "Signed action receipts"
description: "A JWS the user holds: what an agent did, for whom, under which grant — portable evidence that does not require trusting our database."
---

# Signed action receipts

An audit log is **ours**. It answers the admin's question — *what happened on this
platform?* — and it answers it well: hash-chained, tamper-evident, complete.

It does not answer the user's question, which is *what did my agents do, and can I
show that to someone who does not trust your database?*

A receipt does. It is a compact JWS, signed with the same ES256 key as the access
tokens and verifiable against the same public JWKS, stating:

> agent `agent:01J8…`, acting for `user:42` under grant `dgr_01J9…`, asserts it
> performed `orders.create` on `order:9001` at `2026-08-26T00:41:12Z`, with
> outcome `ok`, under PDP decision `dec_01J9…`.

## What the signature attests — and what it does not

The issuer vouches for the **identity binding**: that the actor really was that
agent, really was acting for that user, really under that grant, and that the grant
was **live at that moment**.

It does **not** vouch for the truth of the action. That part is the actor's
assertion.

This distinction is not pedantry. Without it someone will read a receipt as proof
the order shipped. What a receipt proves is that *that agent said so*, in a document
it cannot repudiate — which makes it evidence **against** an agent that lies, not a
way to frame one.

## Who can mint one

Only the holder of a valid **delegated token** for that grant.

```http
POST /iam/agent/receipts
Authorization: Bearer <delegated access token>

{ "action": "orders.create", "resource": "order:9001", "outcome": "ok",
  "decision_id": "dec_01J9…", "idempotency_key": "req-7731" }
```

`sub`, `act` and `pds_dgr` are copied **from the verified token**, never from the
body. The body says only *what was done*. So an agent cannot sign for another
agent, cannot sign for a user who never delegated to it, and cannot invent the
grant it acted under.

Five refusals, each a test in the shipped suite:

| | |
|---|---|
| No token, or a token this issuer did not sign | refused |
| A **plain user token** (no `act`) | refused — it would make a user sign as if they were an agent |
| The grant is revoked or expired | refused — otherwise an agent just cut off could backdate its own history, exactly when it most wants to |
| The agent is suspended or retired | refused |
| Delegation is **frozen** | refused — signing is an action |

The client always gets the same generic `receipt_not_issued`. Telling an agent
*why* it could not sign teaches it how to try better; the detailed reason goes to
the `delegation` audit stream, where it is useful.

## The user's timeline

```http
GET /iam/me/delegations/receipts
```

Every row carries its own JWS, so the user can export it and have it verified by
anyone with the public JWKS — without asking us for anything. That is the whole
difference between an audit (ours, for admins) and a receipt (theirs).

## Two halves, on purpose

A receipt is stored as **the JWS** and **a digest of its canonical claims**.

- The **JWS** is the portable half. It travels, it verifies anywhere.
- The **digest** is the durable half. It is sealed into the tamper-evident audit
  chain, so the receipt remains probative after the signing key leaves the JWKS
  through rotation — which, on a horizon of years, it will.

`exp` is set ten years out and is a formality: evidence does not expire, but the
`TokenSigner` contract requires an expiry. What actually bounds external
verification is key rotation. If you need decade-scale third-party verification,
archive your historical JWKS.

## Not an access token

A receipt is a JWT signed by the same issuer, with `sub` = the user — which is
exactly the shape a careless resource server might accept as authority. So every
receipt carries a dedicated audience that no resource registers:

```
aud: urn:padosoft:iam:delegation-receipt
pds_att: actor
```

Any resource server that validates `aud` — the posture already required for
delegated tokens — rejects it. `verify()` checks both, so a delegated access token
handed to it as "a receipt" is refused rather than parsed.

Receipts carry **no action parameters**. A receipt ends up in a user timeline, an
export, possibly a dispute; call arguments are where PII hides. `action` and
`resource` say what happened, and the detail stays in the audit, where GDPR
crypto-shredding already exists.

## Configuration

```php
'receipts' => [
    'enabled' => env('IAM_AGENTS_RECEIPTS_ENABLED', true),
    'rate_limit' => env('IAM_AGENTS_RECEIPTS_RATE_LIMIT', '120,1'),
    'ttl_seconds' => env('IAM_AGENTS_RECEIPTS_TTL', 315360000),
],
```

On by default: minting still requires a valid delegated token and a live grant, so
the surface does not exist until a delegation does.

## Verifying one yourself

```php
use Padosoft\Iam\Agents\Receipts\DelegationReceiptService;

$receipt = app(DelegationReceiptService::class)->verify($jws);

$receipt->subject;   // user:42
$receipt->agent;     // agent:01J8…
$receipt->action;    // orders.create
$receipt->outcome;   // ok
```

Outside the platform, verify the JWS against `/.well-known/jwks.json` with any JOSE
library, then check `aud` and `pds_att` exactly as above.
