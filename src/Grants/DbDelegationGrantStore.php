<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Grants;

use Padosoft\Iam\Agents\Audit\DelegationAudit;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Contracts\Delegation\ActorRef;
use Padosoft\Iam\Contracts\Delegation\DelegationGrant;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStore;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Store delle deleghe su DB. Ogni mutazione è auditata (hash-chain, stream=delegation).
 * La revoca è soft (status + evidenza chi/quando), idempotente su grant già revocata.
 */
final class DbDelegationGrantStore implements DelegationGrantStore
{
    public function __construct(private readonly DelegationAudit $audit) {}

    public function findActive(SubjectRef $user, SubjectRef $agent): ?DelegationGrant
    {
        if ($agent->type !== ActorRef::SUBJECT_TYPE) {
            return null;
        }

        $grant = DelegationGrantModel::query()
            ->where('user_type', $user->type)
            ->where('user_id', $user->id)
            ->where('agent_id', $agent->id)
            ->where('status', DelegationGrantStatus::Active->value)
            ->where('expires_at', '>', now())
            ->orderByDesc('expires_at')
            ->first();

        return $grant?->toContract();
    }

    public function find(string $grantId): ?DelegationGrant
    {
        if ($grantId === '') {
            return null;
        }

        return DelegationGrantModel::query()->find($grantId)?->toContract();
    }

    public function listFor(SubjectRef $user): iterable
    {
        $grants = DelegationGrantModel::query()
            ->where('user_type', $user->type)
            ->where('user_id', $user->id)
            ->orderByDesc('created_at')
            ->get();

        foreach ($grants as $grant) {
            yield $grant->toContract();
        }
    }

    public function revoke(string $grantId, SubjectRef $revokedBy): void
    {
        $grant = DelegationGrantModel::query()->find($grantId);
        if ($grant === null || $grant->status === DelegationGrantStatus::Revoked->value) {
            return; // idempotente: revocare una grant assente o già revocata è un no-op
        }

        $grant->fill([
            'status' => DelegationGrantStatus::Revoked->value,
            'revoked_at' => now(),
            'revoked_by_type' => $revokedBy->type,
            'revoked_by_id' => $revokedBy->id,
        ])->save();

        $this->audit->grantRevoked($grant, $revokedBy);
    }
}
