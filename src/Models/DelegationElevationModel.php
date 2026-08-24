<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

/**
 * Una richiesta di JIT scope elevation (v1.1): l'agente ha chiesto scope FUORI
 * dalla grant; il delegante approva con un RI-consenso step-up o nega. `pending`
 * scade da solo a `expires_at` (fail-closed: una richiesta ignorata non eleva).
 *
 * @property string $id
 * @property string $grant_id
 * @property array<array-key, mixed> $requested_scopes
 * @property string $reason
 * @property string $status
 * @property Carbon $expires_at
 * @property string|null $consent_confirmation_id
 * @property string|null $consent_aal
 * @property Carbon|null $decided_at
 * @property Carbon|null $created_at
 */
final class DelegationElevationModel extends Model
{
    public const STATUS_PENDING = 'pending';

    public const STATUS_APPROVED = 'approved';

    public const STATUS_DENIED = 'denied';

    public const STATUS_EXPIRED = 'expired';

    protected $table = 'iam_delegation_elevations';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = [
        'id', 'grant_id', 'requested_scopes', 'reason', 'status',
        'expires_at', 'consent_confirmation_id', 'consent_aal', 'decided_at',
    ];

    protected $casts = [
        'requested_scopes' => 'array',
        'expires_at' => 'datetime',
        'decided_at' => 'datetime',
    ];

    public static function newId(): string
    {
        return 'elv_'.Str::ulid()->toBase32();
    }

    /** La richiesta è ancora decidibile ADESSO (pending e non scaduta). Fail-closed. */
    public function isPendingAt(\DateTimeInterface $now): bool
    {
        return $this->status === self::STATUS_PENDING && $now < $this->expires_at;
    }
}
