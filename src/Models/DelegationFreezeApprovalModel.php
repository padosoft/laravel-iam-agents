<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Una approvazione alla rimozione di un freeze, da UN admin.
 *
 * L'unique `(freeze_id, approver)` è il quorum stesso: senza di esso una singola
 * identità che approva m volte soddisfa un quorum di m, e l'asimmetria — uno per
 * fermare, molti per ripartire — non esiste più.
 *
 * @property int $id
 * @property string $freeze_id
 * @property string $approver
 * @property string|null $note
 * @property Carbon $approved_at
 */
final class DelegationFreezeApprovalModel extends Model
{
    protected $table = 'iam_delegation_freeze_approvals';

    public $timestamps = false;

    protected $fillable = ['freeze_id', 'approver', 'note', 'approved_at'];

    protected $casts = ['approved_at' => 'datetime'];
}
