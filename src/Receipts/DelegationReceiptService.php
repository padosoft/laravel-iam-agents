<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Receipts;

use DateTimeImmutable;
use Padosoft\Iam\Agents\Audit\DelegationAudit;
use Padosoft\Iam\Agents\Freeze\DelegationFreezeService;
use Padosoft\Iam\Agents\Freeze\DelegationFrozenException;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationReceiptModel;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Contracts\Delegation\ActClaim;
use Padosoft\Iam\Contracts\Delegation\ActorRef;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStore;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Throwable;

/**
 * Emissione e verifica delle ricevute d'azione delegata.
 *
 * **Chi può coniarne una: solo chi ha il token delegato.** L'endpoint di
 * emissione riceve il token delegato come credenziale, e `sub`, `act` e
 * `pds_dgr` sono copiati DAL TOKEN VERIFICATO, mai dal body. Un agente non può
 * quindi firmare una ricevuta per conto di un altro, né per un utente che non
 * gli ha delegato niente — e la ricevuta che firma è, per costruzione, evidenza
 * che non può ripudiare.
 *
 * **Cosa NON è.** Una ricevuta non è un'autorizzazione, non prova che l'azione
 * sia andata a buon fine e non sostituisce l'audit. È evidenza portabile: la
 * catena hash-chained è nostra, la ricevuta è dell'utente.
 *
 * **Perché la grant deve essere ancora viva.** Senza quel controllo un agente
 * appena revocato potrebbe retrodatare la propria storia firmando ricevute di
 * azioni mai avvenute, esattamente nel momento in cui ha più interesse a farlo.
 * Per la stessa ragione una delega congelata non conia: firmare è un'azione.
 */
final class DelegationReceiptService
{
    /** Dieci anni. Vedi {@see ttl()} per perché `exp` qui è quasi una formalità. */
    private const DEFAULT_TTL = 315360000;

    public function __construct(
        private readonly TokenSigner $signer,
        private readonly DelegationGrantStore $grants,
        private readonly DelegationAudit $audit,
        private readonly DelegationFreezeService $freeze,
    ) {}

    /**
     * @param  array<string, mixed>  $payload  action / resource / outcome / decision_id / idempotency_key
     *
     * @throws ReceiptException
     */
    public function mint(string $delegatedToken, array $payload): DelegationReceiptModel
    {
        $claims = $this->parseDelegatedToken($delegatedToken);

        $subject = new SubjectRef('user', (string) $claims['sub']);
        $agentRef = $claims['actor']->subject;
        $grantId = (string) $claims['grant_id'];

        $grant = $this->grants->find($grantId);

        if ($grant === null
            || !$grant->isUsableAt(new DateTimeImmutable)
            || (string) $grant->user !== (string) $subject
            || (string) $grant->agent !== (string) $agentRef
        ) {
            throw new ReceiptException('grant_not_usable', 'La grant citata dal token non è più utilizzabile o non corrisponde alla coppia (utente, agente).');
        }

        $agent = Agent::query()->find($agentRef->id);

        if ($agent === null || $agent->statusEnum() !== AgentStatus::Active) {
            throw new ReceiptException('agent_not_active', "L'agente non è attivo: nessuna ricevuta.");
        }

        try {
            $this->freeze->assertNotFrozen($agent->id, $agent->organization_id);
        } catch (DelegationFrozenException $e) {
            throw new ReceiptException($e->reason, 'La delega è congelata: firmare è un\'azione.');
        }

        $action = self::text($payload['action'] ?? null);
        $outcome = self::text($payload['outcome'] ?? null) ?: ActionReceipt::OUTCOME_OK;
        $resource = self::text($payload['resource'] ?? null) ?: null;
        $decisionId = self::text($payload['decision_id'] ?? null) ?: null;
        $idempotencyKey = self::text($payload['idempotency_key'] ?? null) ?: null;

        if ($action === '') {
            throw new ReceiptException('action_missing', 'Una ricevuta senza azione non attesta niente.');
        }

        if (!in_array($outcome, ActionReceipt::OUTCOMES, true)) {
            throw new ReceiptException('outcome_invalid', 'Esito non riconosciuto: '.implode(' | ', ActionReceipt::OUTCOMES).'.');
        }

        if ($idempotencyKey !== null) {
            $existing = DelegationReceiptModel::query()
                ->where('grant_id', $grantId)
                ->where('idempotency_key', $idempotencyKey)
                ->first();

            // Le reti mobili ritentano. Restituire la ricevuta già emessa è
            // l'unica risposta corretta: emetterne una seconda racconterebbe due
            // azioni dove ce n'è stata una.
            if ($existing !== null) {
                return $existing;
            }
        }

        $receipt = new ActionReceipt(
            id: DelegationReceiptModel::newId(),
            subject: $subject,
            agent: $agentRef,
            grantId: $grantId,
            action: $action,
            resource: $resource,
            outcome: $outcome,
            decisionId: $decisionId,
            issuedAt: new DateTimeImmutable,
        );

        $jws = $this->signer->issue($receipt->claims(), $this->ttl());

        $model = new DelegationReceiptModel([
            'id' => $receipt->id,
            'grant_id' => $grantId,
            'agent_id' => $agent->id,
            'subject_type' => $subject->type,
            'subject_id' => $subject->id,
            'action' => $action,
            'resource' => $resource,
            'outcome' => $outcome,
            'decision_id' => $decisionId,
            'issued_at' => $receipt->issuedAt,
            'jws' => $jws,
            'payload_digest' => self::digest($receipt),
            'idempotency_key' => $idempotencyKey,
        ]);
        $model->save();

        $this->audit->receiptIssued($model);

        return $model;
    }

    /**
     * Verifica una ricevuta e restituisce ciò che afferma.
     *
     * Controlla firma, issuer e scadenza (via {@see TokenSigner::parse()}), poi
     * che sia davvero una ricevuta: `aud` dedicata e `pds_att`. Senza quei due
     * controlli un access token delegato — stesso issuer, stessa forma, `sub` =
     * utente — passerebbe da qui come se fosse evidenza di un'azione.
     *
     * @throws ReceiptException
     */
    public function verify(string $jws): ActionReceipt
    {
        try {
            $claims = $this->signer->parse($jws);
        } catch (Throwable) {
            throw new ReceiptException('signature_invalid', 'Firma, issuer o scadenza non validi.');
        }

        $audience = $claims['aud'] ?? null;
        $audiences = array_values(array_filter(is_array($audience) ? $audience : [$audience], 'is_string'));

        if (!in_array(ActionReceipt::AUDIENCE, $audiences, true) || ($claims['pds_att'] ?? null) !== 'actor') {
            throw new ReceiptException('not_a_receipt', 'Il token è firmato da questo issuer ma non è una ricevuta.');
        }

        $actor = self::actorOf($claims[ActClaim::ACT] ?? null);
        $sub = self::text($claims['sub'] ?? null);

        if ($sub === '' || $actor === null) {
            throw new ReceiptException('receipt_malformed', 'Ricevuta senza le due identità.');
        }

        return new ActionReceipt(
            id: self::text($claims['jti'] ?? null),
            subject: self::subjectOf($sub),
            agent: $actor->subject,
            grantId: self::text($claims[ActClaim::CLAIM_DELEGATION_GRANT] ?? null),
            action: self::text($claims['pds_act'] ?? null),
            resource: self::text($claims['pds_res'] ?? null) ?: null,
            outcome: self::text($claims['pds_out'] ?? null),
            decisionId: self::text($claims['pds_dec'] ?? null) ?: null,
            issuedAt: self::instantOf($claims['iat'] ?? null),
        );
    }

    public static function digest(ActionReceipt $receipt): string
    {
        return 'sha256:'.hash('sha256', json_encode($receipt->claims(), JSON_THROW_ON_ERROR));
    }

    /**
     * Un claim o un campo del body letto come stringa. Qualunque cosa che NON sia
     * una stringa diventa stringa vuota, che ogni chiamante tratta come assenza:
     * un client che manda `action: {...}` sta sbagliando, e trasformarlo in
     * "Array" con un cast sarebbe peggio che rifiutarlo.
     */
    private static function text(mixed $value): string
    {
        return is_string($value) ? trim($value) : '';
    }

    /**
     * Il livello corrente del claim `act` come attore, o null.
     *
     * Ricostruisce l'array con la sola chiave `sub` invece di passare il claim
     * grezzo: `ActorRef::fromActClaim()` vuole una mappa a chiavi stringa, e un
     * claim che arriva dalla rete non ha nessun obbligo di esserlo.
     */
    private static function actorOf(mixed $act): ?ActorRef
    {
        if (!is_array($act)) {
            return null;
        }

        $sub = $act['sub'] ?? null;

        return is_string($sub) ? ActorRef::fromActClaim(['sub' => $sub]) : null;
    }

    /**
     * `iat` torna come timestamp o già come oggetto data, a seconda della libreria
     * JWT che il signer usa sotto. Accettare entrambi è più onesto che scommettere
     * su una delle due e rompersi al primo aggiornamento dell'implementazione.
     */
    private static function instantOf(mixed $iat): DateTimeImmutable
    {
        if ($iat instanceof \DateTimeInterface) {
            return DateTimeImmutable::createFromInterface($iat);
        }

        return (new DateTimeImmutable)->setTimestamp(is_numeric($iat) ? (int) $iat : 0);
    }

    /**
     * `user:42` → SubjectRef. Un `sub` senza prefisso è trattato come utente:
     * è ciò che l'issuer emette, e inventare un tipo diverso sarebbe peggio che
     * assumere quello.
     */
    private static function subjectOf(string $sub): SubjectRef
    {
        $parts = explode(':', $sub, 2);

        return count($parts) === 2 && $parts[0] !== '' && $parts[1] !== ''
            ? new SubjectRef($parts[0], $parts[1])
            : new SubjectRef('user', $sub);
    }

    /**
     * I claim di identità estratti dal token delegato, tutti obbligatori.
     *
     * @return array{sub: string, actor: ActorRef, grant_id: string}
     *
     * @throws ReceiptException
     */
    private function parseDelegatedToken(string $token): array
    {
        if (trim($token) === '') {
            throw new ReceiptException('token_missing', 'Nessun token delegato presentato.');
        }

        try {
            $claims = $this->signer->parse($token);
        } catch (Throwable) {
            throw new ReceiptException('token_invalid', 'Token delegato con firma, issuer o scadenza non validi.');
        }

        $actor = self::actorOf($claims[ActClaim::ACT] ?? null);
        $sub = self::text($claims['sub'] ?? null);
        $grantId = self::text($claims[ActClaim::CLAIM_DELEGATION_GRANT] ?? null);

        // Un token SENZA `act` è un token utente pieno: coniare da lì significherebbe
        // far firmare all'utente una ricevuta come se fosse un agente.
        if ($actor === null || $sub === '' || $grantId === '') {
            throw new ReceiptException('token_not_delegated', 'Solo un token delegato (act + pds_dgr) può coniare una ricevuta.');
        }

        return ['sub' => $sub, 'actor' => $actor, 'grant_id' => $grantId];
    }

    /**
     * Una ricevuta non scade: l'evidenza non scade. `exp` è imposto dal contratto
     * `TokenSigner`, quindi è messo molto lontano e resta una formalità.
     *
     * Ciò che limita davvero la verifica è la ROTAZIONE DELLE CHIAVI: quando il
     * `kid` esce dal JWKS, il JWS non è più verificabile da terzi. È il motivo per
     * cui la ricevuta ha due metà — il digest sigillato nella catena d'audit resta
     * probante anche dopo. Chi ha bisogno di verifica esterna su orizzonti di anni
     * archivia il JWKS storico.
     */
    private function ttl(): int
    {
        $ttl = config('iam-agents.receipts.ttl_seconds', self::DEFAULT_TTL);

        return max(60, is_numeric($ttl) ? (int) $ttl : self::DEFAULT_TTL);
    }
}
