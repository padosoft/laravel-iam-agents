<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Agents\Audit\DelegationAudit;
use Padosoft\Iam\Agents\Receipts\DelegationReceiptService;
use Padosoft\Iam\Agents\Receipts\ReceiptException;

/**
 * L'endpoint con cui un agente firma ciò che ha fatto.
 *
 * L'autenticazione è il TOKEN DELEGATO stesso, in `Authorization: Bearer` — non
 * una sessione, non una chiave d'app. È il punto di tutto il disegno: le identità
 * della ricevuta (`sub` = utente, `act` = agente, `pds_dgr` = grant) sono copiate
 * dal token verificato, mai dal body, quindi nessun agente può firmare per un
 * altro né per un utente che non gli ha delegato niente. Il body porta soltanto
 * cosa è stato fatto.
 *
 * Il rifiuto è sempre generico. Dire a un agente *perché* non ha potuto firmare
 * gli insegnerebbe come provarci meglio; il motivo dettagliato resta nell'audit,
 * dove serve davvero.
 */
final class AgentReceiptsController
{
    public function __construct(
        private readonly DelegationReceiptService $receipts,
        private readonly DelegationAudit $audit,
    ) {}

    public function store(Request $request): JsonResponse
    {
        try {
            $receipt = $this->receipts->mint($request->bearerToken() ?? '', [
                'action' => $request->string('action')->toString(),
                'resource' => $request->string('resource')->toString(),
                'outcome' => $request->string('outcome', 'ok')->toString(),
                'decision_id' => $request->string('decision_id')->toString(),
                'idempotency_key' => $request->string('idempotency_key')->toString(),
            ]);
        } catch (ReceiptException $e) {
            $this->audit->receiptRefused($e->reason);

            return new JsonResponse(['error' => 'receipt_not_issued'], 422);
        }

        return new JsonResponse([
            'data' => [
                'id' => $receipt->id,
                'issued_at' => $receipt->issued_at->toDateTimeImmutable()->format(\DateTimeInterface::ATOM),
                'payload_digest' => $receipt->payload_digest,
                // Il JWS torna all'agente perché è LUI ad averlo firmato: deve
                // poterlo allegare alla propria risposta, alla ricevuta che mostra
                // all'utente, al ticket che apre. Non è un segreto — è
                // un'attestazione che lo vincola.
                'receipt' => $receipt->jws,
            ],
        ], 201);
    }
}
