<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Receipts;

use RuntimeException;

/**
 * Una ricevuta non è emettibile: token delegato assente o invalido, grant non
 * più viva, delega congelata, esito o azione malformati.
 *
 * `reason` è il motivo MACCHINA che finisce nell'audit; il messaggio è per
 * l'operatore. Al client va sempre e solo una forma generica: dire a un agente
 * *perché* non ha potuto firmare gli insegna come provarci meglio.
 */
final class ReceiptException extends RuntimeException
{
    public function __construct(public readonly string $reason, string $message)
    {
        parent::__construct($message);
    }
}
