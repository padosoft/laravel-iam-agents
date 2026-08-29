---
title: "Access reviews for delegations"
description: "Delegation grants become certifiable items in the IAM access-review campaigns: who reviews them, the signals that surface a forgotten delegation, and why including them is an explicit choice."
---

# Access reviews for delegations

A delegation grant is a standing permission, given by a human, for an agent to act on their behalf. That is an access — and accesses get re-examined, or they quietly accumulate.

From `laravel-iam-agents` v1.6 the module registers itself as a **reviewable source** in the IAM server's access-review engine (IGA), so a certification campaign can look delegations in the face alongside ordinary RBAC/ABAC grants.

::: callout warning "Nobody leaves the company on an agent's behalf"
A role granted to a person eventually gets revoked because the person moves team or leaves — the organisation has a process that notices. An agent has no such lifecycle event. A delegation that stopped being necessary six months ago is still there, still valid, still exchangeable for a token, and nothing in the ordinary course of business will point at it. That is exactly what a review campaign is for.
:::

## Including delegations in a campaign

Deliberately **opt-in**. A campaign's `scope_json.reviewable_types` names the sources it certifies; when the key is absent the campaign behaves as it always has — grants only.

```json
POST /api/iam/v1/access-reviews/campaigns
{
  "name": "Q3 — delegations",
  "on_unconfirmed": "revoke",
  "scope_json": {
    "reviewable_types": ["delegation_grant"]
  }
}
```

Installing this module must not make delegations appear inside campaigns somebody already planned and scheduled. So they never appear unless asked for.

Both kinds in one campaign:

```json
"scope_json": { "reviewable_types": ["grant", "delegation_grant"] }
```

Narrow to specific agents:

```json
"scope_json": {
  "reviewable_types": ["delegation_grant"],
  "agent_ids": ["agt_01J8...", "agt_01J9..."]
}
```

Only **active, unexpired** grants are certified: a revoked or expired delegation is not an access any more, and asking somebody to certify it would waste the one thing a review campaign spends — reviewer attention.

## Who reviews a delegation

By default, **the delegating user**. They gave the consent, and they are the only person who actually knows whether the agent is still needed. The item lands in their queue as `user:<their id>`.

A campaign with `reviewer_strategy: "named"` and a `reviewer` in its scope overrides that — a compliance function running a centralised audit must be able to take the decision itself.

## The signals

Each item carries an immutable snapshot, frozen when the campaign opens, meant to answer "should this still exist?" before the reviewer has to think:

| Signal | What it tells the reviewer |
| --- | --- |
| `never_used` | The delegation was granted and never once acted on. |
| `dormant` | Never used, or unused for longer than the threshold. |
| `last_used_days` | Days since the last **signed receipt** — real actions, not token issuance. |
| `expires_in_days` | How long it has left anyway (negative would mean expired). |
| `agent_status` / `agent_suspended` | The agent's lifecycle state right now. |
| `scopes_count` | How wide the delegation is. |
| `consent_aal` | The assurance level at which consent was actually given. |
| `has_budget` | Whether a spend ceiling bounds it. |

Two of these deserve a note:

**`last_used_days` comes from the [signed action receipts](/guides/action-receipts)**, not from a `last_used_at` column updated on every touch. Receipts record what the delegation *did*; a token exchange only records that somebody asked. "Used" should mean the former.

**`agent_suspended` is the case to close first.** A suspended agent still holds live delegations, and lifting the suspension brings them all back without anyone re-confirming anything. Revoking the delegations of a suspended agent is how you make sure the return is deliberate.

The dormancy threshold defaults to **30 days**, not the 90 used for RBAC grants — a delegation has a shorter natural life, and a month of silence is already a good reason to ask:

```php
// config/iam-agents.php
'reviews' => [
    'unused_days' => (int) env('IAM_AGENTS_REVIEW_UNUSED_DAYS', 30),
],
```

## What a decision does

**Revoke** goes through the delegation grant store, not a bare `UPDATE`: the grant is revoked, the `delegation` audit stream records it, and `DelegationGrantRevoked` fires — so the consumers listening for it (anomaly detection, FinOps, compliance) see it exactly as they would see any other revocation. The campaign id and the review item id ride along in the audit metadata, so the revocation is traceable back to the campaign that caused it.

**Approve** touches nothing. It certifies that the delegation is still wanted.

**On close**, `on_unconfirmed` applies to whatever is still pending: `revoke` closes them, `keep` certifies them, and `suspend` — which delegations have no state for — is treated as revoke, fail-closed.

Revocation is idempotent: a grant already revoked or already gone is a no-op, not an error.

## If the module is uninstalled

The server keeps the items — they are audit evidence, and evidence does not disappear with the thing it describes — but it cannot revoke what it can no longer reach. Such an item stays `pending`, is audited as `iam.access_review.item_unrevocable`, and does not block the campaign from closing for everything else.

Marking it `revoked` anyway would write into the audit trail a revocation that never happened, which is the one thing an IGA system cannot afford.

## In the admin API

Items expose the shared fields (`subject_type`, `subject_id`, `privilege_type`, `privilege_key`, `application_key`, `effect`) so one table renders both kinds, plus the ones only a delegation has: `agent_id`, `agent_name`, `purpose`, `expires_at`, `grant_status`.

```
GET /api/iam/v1/access-reviews/campaigns/{id}/items
```

The `privilege_key` of a delegation is its scope list; `privilege_type` is `delegation`.

## See also

- [Signed action receipts](/guides/action-receipts) — where `last_used_days` comes from
- [The asymmetric kill switch](/guides/kill-switch) — stopping everything now, versus certifying over time
- [Consent](/guides/consent) — how the grant came to exist in the first place
