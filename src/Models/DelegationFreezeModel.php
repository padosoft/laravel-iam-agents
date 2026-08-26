<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Models;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Padosoft\Iam\Agents\Freeze\FreezeScope;

/**
 * Un freeze della delega: attivo finché `lifted_at` è null.
 *
 * `required_quorum` è uno SNAPSHOT del valore di config al momento del freeze, non
 * una lettura differita. È la decisione portante dell'intera feature: se il quorum
 * si rileggesse alla rimozione, chiunque possa modificare la config lo porterebbe a
 * 1 e scongelerebbe da solo — e un controllo aggirabile da chi si sta difendendo
 * non è un controllo.
 *
 * @property string $id
 * @property string $scope
 * @property string|null $scope_id
 * @property string $reason
 * @property string $frozen_by
 * @property Carbon $frozen_at
 * @property int $required_quorum
 * @property Carbon|null $lifted_at
 * @property string|null $lifted_by
 * @property-read Collection<int, DelegationFreezeApprovalModel> $approvals
 */
final class DelegationFreezeModel extends Model
{
    protected $table = 'iam_delegation_freezes';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = [
        'id', 'scope', 'scope_id', 'reason', 'frozen_by', 'frozen_at',
        'required_quorum', 'lifted_at', 'lifted_by',
    ];

    protected $casts = [
        'frozen_at' => 'datetime',
        'lifted_at' => 'datetime',
        'required_quorum' => 'integer',
    ];

    public static function newId(): string
    {
        return 'frz_'.Str::ulid()->toBase32();
    }

    /** @return HasMany<DelegationFreezeApprovalModel, $this> */
    public function approvals(): HasMany
    {
        return $this->hasMany(DelegationFreezeApprovalModel::class, 'freeze_id');
    }

    public function isActive(): bool
    {
        return $this->lifted_at === null;
    }

    public function scopeEnum(): FreezeScope
    {
        return FreezeScope::from($this->scope);
    }

    /**
     * Quante approvazioni distinte mancano ancora. Mai negativo: un freeze che ha
     * raccolto più approvazioni del necessario (una corsa fra due admin) è
     * semplicemente pronto.
     */
    public function remainingApprovals(int $collected): int
    {
        return max(0, $this->required_quorum - $collected);
    }
}
