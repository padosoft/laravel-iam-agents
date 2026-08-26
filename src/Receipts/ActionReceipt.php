<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Receipts;

use DateTimeImmutable;
use DateTimeInterface;
use Padosoft\Iam\Contracts\Delegation\ActClaim;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Il contenuto di una ricevuta d'azione delegata, prima della firma.
 *
 * **Cosa attesta la firma, esattamente.** L'issuer garantisce il LEGAME DI
 * IDENTITÀ — che l'attore era davvero quell'agente, che agiva davvero per
 * quell'utente, sotto quella grant, e che la grant era viva in quel momento —
 * NON la verità dell'azione. La verità dell'azione è un'asserzione dell'attore.
 *
 * La distinzione non è pedanteria: senza, qualcuno tratterà una ricevuta come
 * prova che l'ordine è partito. Ciò che la ricevuta prova è che *quell'agente*
 * ha dichiarato di averlo fatto, in un documento che non può ripudiare — il che
 * la rende evidenza CONTRO un agente che mente, non un modo per incastrarlo.
 *
 * Perché esiste, accanto a un audit già hash-chained: la catena è NOSTRA. Una
 * ricevuta è evidenza portabile che tiene l'UTENTE, e che può mostrare a
 * qualcuno che non si fida del nostro database.
 */
final readonly class ActionReceipt
{
    /**
     * `aud` dedicata. Non è decorazione: una ricevuta è un JWT firmato dallo
     * stesso issuer degli access token, con `sub` = utente — cioè esattamente la
     * forma che un resource server distratto potrebbe accettare come autorità.
     * Una `aud` che nessuna resource registra rende quel fraintendimento
     * impossibile per chiunque validi `aud`, che è la difesa già stabilita per i
     * token delegati. (L'header `typ` non è impostabile attraverso il contratto
     * `TokenSigner`, quindi la difesa vive nei claim, dove è comunque firmata.)
     */
    public const AUDIENCE = 'urn:padosoft:iam:delegation-receipt';

    public const OUTCOME_OK = 'ok';

    public const OUTCOME_FAILED = 'failed';

    public const OUTCOME_DENIED = 'denied';

    /** @var list<string> */
    public const OUTCOMES = [self::OUTCOME_OK, self::OUTCOME_FAILED, self::OUTCOME_DENIED];

    public function __construct(
        public string $id,
        public SubjectRef $subject,
        public SubjectRef $agent,
        public string $grantId,
        public string $action,
        public ?string $resource,
        public string $outcome,
        public ?string $decisionId,
        public DateTimeImmutable $issuedAt,
    ) {}

    /**
     * I claim firmati. Deliberatamente NON contengono i parametri dell'azione:
     * una ricevuta finisce in un timeline utente, in un export, forse in una
     * disputa — e gli argomenti di una chiamata sono il posto dove la PII si
     * annida. `action` e `resource` bastano a dire cosa è successo; il dettaglio
     * vive nell'audit, dove il crypto-shredding GDPR esiste già.
     *
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        return array_filter([
            'jti' => $this->id,
            'aud' => self::AUDIENCE,
            'sub' => (string) $this->subject,
            ActClaim::ACT => ['sub' => (string) $this->agent],
            ActClaim::CLAIM_DELEGATION_GRANT => $this->grantId,
            'pds_act' => $this->action,
            'pds_res' => $this->resource,
            'pds_out' => $this->outcome,
            'pds_dec' => $this->decisionId,
            'pds_att' => 'actor',
            'iat' => $this->issuedAt->getTimestamp(),
        ], static fn (mixed $v): bool => $v !== null);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'subject' => (string) $this->subject,
            'agent' => (string) $this->agent,
            'grant_id' => $this->grantId,
            'action' => $this->action,
            'resource' => $this->resource,
            'outcome' => $this->outcome,
            'decision_id' => $this->decisionId,
            'issued_at' => $this->issuedAt->format(DateTimeInterface::ATOM),
        ];
    }
}
