<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Padosoft\Iam\Contracts\Assurance\Aal;
use Padosoft\Iam\Contracts\Delegation\ActorRef;
use Padosoft\Iam\Contracts\Delegation\DelegationBudget;
use Padosoft\Iam\Contracts\Delegation\DelegationGrant;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStatus;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Persistenza di una DelegationGrant (il VO dei contracts è la vista immutabile;
 * questo è il record). `consent_confirmation_id` è UNIQUE: consumazione one-shot
 * della conferma step-up — la stessa evidenza non crea mai due grant.
 *
 * @property string $id
 * @property string $user_type
 * @property string $user_id
 * @property string $agent_id
 * @property array<int, string> $scopes
 * @property string $purpose
 * @property string $status
 * @property Carbon $expires_at
 * @property string|null $consent_confirmation_id
 * @property array<array-key, mixed>|null $budget
 * @property string|null $consent_aal
 * @property Carbon|null $revoked_at
 * @property string|null $revoked_by_type
 * @property string|null $revoked_by_id
 * @property Carbon|null $created_at
 */
final class DelegationGrantModel extends Model
{
    protected $table = 'iam_delegation_grants';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = [
        'id', 'user_type', 'user_id', 'agent_id', 'scopes', 'purpose', 'budget', 'status',
        'expires_at', 'consent_confirmation_id', 'consent_aal',
        'revoked_at', 'revoked_by_type', 'revoked_by_id',
    ];

    protected $casts = [
        'scopes' => 'array',
        'budget' => 'array',
        'expires_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];

    public static function newId(): string
    {
        return 'dgr_'.Str::ulid()->toBase32();
    }

    public function toContract(): DelegationGrant
    {
        $scopes = [];
        foreach ($this->scopes as $scope) {
            if (is_string($scope) && $scope !== '') {
                $scopes[] = $scope;
            }
        }

        return new DelegationGrant(
            id: $this->id,
            user: new SubjectRef($this->user_type, $this->user_id),
            agent: new SubjectRef(ActorRef::SUBJECT_TYPE, $this->agent_id),
            scopes: $scopes,
            purpose: $this->purpose,
            // Stato sconosciuto ⇒ Suspended: non autorizza (fail-closed), ma non è terminale.
            status: DelegationGrantStatus::tryFrom($this->status) ?? DelegationGrantStatus::Suspended,
            expiresAt: $this->expires_at->toDateTimeImmutable(),
            createdAt: ($this->created_at ?? now())->toDateTimeImmutable(),
            consentConfirmationId: $this->consent_confirmation_id,
            consentAal: $this->consent_aal !== null ? Aal::fromString($this->consent_aal) : null,
            revokedAt: $this->revoked_at?->toDateTimeImmutable(),
            revokedBy: ($this->revoked_by_type !== null && $this->revoked_by_id !== null)
                ? new SubjectRef($this->revoked_by_type, $this->revoked_by_id)
                : null,
            budget: is_array($this->budget) && $this->budget !== [] ? DelegationBudget::fromArray($this->budget) : null,
        );
    }
}
