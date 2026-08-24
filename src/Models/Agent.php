<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Padosoft\Iam\Contracts\Delegation\ActorRef;
use Padosoft\Iam\Contracts\Delegation\AgentDescriptor;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Agente registrato: identità di prima classe (SubjectRef `agent:{id}`), con operator,
 * owner, tetto di scope da manifest e lifecycle fail-closed (solo `active` delega).
 *
 * @property string $id
 * @property string $name
 * @property string|null $operator
 * @property string|null $owner_type
 * @property string|null $owner_id
 * @property string|null $application_key
 * @property string|null $client_id
 * @property array<int, string> $max_scopes
 * @property string $status
 * @property string|null $organization_id
 * @property Carbon|null $approved_at
 * @property string|null $approved_by
 */
final class Agent extends Model
{
    protected $table = 'iam_agents';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = [
        'id', 'name', 'operator', 'owner_type', 'owner_id', 'application_key',
        'client_id', 'max_scopes', 'status', 'organization_id',
        'approved_at', 'approved_by', 'suspended_at', 'retired_at',
    ];

    protected $casts = [
        'max_scopes' => 'array',
        'approved_at' => 'datetime',
        'suspended_at' => 'datetime',
        'retired_at' => 'datetime',
    ];

    public static function newId(): string
    {
        return 'agt_'.Str::ulid()->toBase32();
    }

    public function subject(): SubjectRef
    {
        return new SubjectRef(ActorRef::SUBJECT_TYPE, $this->id);
    }

    public function statusEnum(): AgentStatus
    {
        return AgentStatus::tryFrom($this->status) ?? AgentStatus::Suspended; // sconosciuto ⇒ non delega (fail-closed)
    }

    public function toDescriptor(): AgentDescriptor
    {
        $maxScopes = [];
        foreach ($this->max_scopes as $scope) {
            if (is_string($scope) && $scope !== '') {
                $maxScopes[] = $scope;
            }
        }

        $owner = ($this->owner_type !== null && $this->owner_id !== null)
            ? new SubjectRef($this->owner_type, $this->owner_id)
            : null;

        return new AgentDescriptor(
            subject: $this->subject(),
            status: $this->statusEnum(),
            maxScopes: $maxScopes,
            operator: $this->operator,
            owner: $owner,
            applicationId: $this->application_key,
        );
    }
}
