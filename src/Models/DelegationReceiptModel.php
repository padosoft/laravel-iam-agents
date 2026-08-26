<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

/**
 * Una ricevuta d'azione delegata, persistita.
 *
 * Due metà, deliberatamente diverse. Il **JWS** è la metà portabile: l'utente la
 * esporta e chiunque la verifica col JWKS, senza chiedere niente a noi. Il
 * **`payload_digest`** è la metà durevole: viene sigillato nella catena d'audit
 * hash-chained, così la ricevuta resta probante anche dopo che la chiave di firma
 * è uscita dal JWKS per rotazione — il che, su orizzonti di anni, succede.
 *
 * Append-only: una ricevuta non si modifica e non si cancella. La cancellazione
 * dell'utente passa dal crypto-shredding del `sub`, come per il resto della
 * catena.
 *
 * @property string $id
 * @property string $grant_id
 * @property string $agent_id
 * @property string $subject_type
 * @property string $subject_id
 * @property string $action
 * @property string|null $resource
 * @property string $outcome
 * @property string|null $decision_id
 * @property Carbon $issued_at
 * @property string $jws
 * @property string $payload_digest
 * @property string|null $idempotency_key
 */
final class DelegationReceiptModel extends Model
{
    protected $table = 'iam_delegation_receipts';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = [
        'id', 'grant_id', 'agent_id', 'subject_type', 'subject_id',
        'action', 'resource', 'outcome', 'decision_id',
        'issued_at', 'jws', 'payload_digest', 'idempotency_key',
    ];

    protected $casts = ['issued_at' => 'datetime'];

    public static function newId(): string
    {
        return 'rcp_'.Str::ulid()->toBase32();
    }
}
