---
title: Glossary (junior-proof)
description: The five terms delegation is built on — sub, act, delegation grant, intersection, introspection — each with a concrete example.
---

# Glossary — junior-proof

Five terms. Understand these and every other page reads easily.

## `sub` — the subject

*Who the action is **for**.* In a delegated token, `sub` is always the **human user** who delegated
(`"sub": "user:42"`). It is never the agent. When order #981 gets drafted, it gets drafted in
user 42's account, under user 42's data-protection rights.

## `act` — the actor

*Who is **performing** the action.* An RFC 8693 claim: `"act": {"sub": "agent:01J8XKQ0V2"}`. When an
agent acts through another agent (multi-hop, v2), the chain nests:
`{"act": {"sub": "agent:B", "act": {"sub": "agent:A"}}}` — read it outermost-first: *B is acting now,
and it got there via A*. An `act` claim that is malformed **throws** during parsing — it never
silently degrades into "just the user's token", because that would let a broken agent impersonate
its user.

## Delegation grant

*The user's recorded consent.* A row that says: user 42 allows agent `01J8…` to use scopes
`orders:read, orders:draft`, for purpose *"Draft weekly order proposals"*, until date X — confirmed
with step-up evidence (AAL + confirmation id). The grant id travels in the token as the private
claim **`pds_dgr`**, so revoking the grant kills every token that cites it at the **next check**,
not at token expiry.

## The intersection

*What the delegated pair may actually do:* `authority = user's permissions ∩ agent's permissions ∩
granted scopes`. **Never the union.** The user can delete orders but the agent was never given
`orders:delete`? Denied. The agent has `refunds:issue` but this user doesn't? Denied. Either layer
saying no wins (deny-overrides). See [The intersection rule](/concepts/intersection-rule).

## Introspection-mandatory

*How a resource server verifies a delegated token:* it asks the IAM server (`POST /oauth/introspect`)
instead of trusting local signature parsing. The server's answer also checks that the delegating
user's **session is still alive** and returns the authoritative claims. Local parsing of a delegated
token is only routing; the `typ: delegated+jwt` header is hygiene. The defence is the server's
answer — that is what makes revocation land at the next request instead of at token expiry.

---

**One sentence to rule them all:** *a delegated token says "`act` is doing this **for** `sub`, under
grant `pds_dgr`" — and every check re-asks all three, fresh, fail-closed.*
