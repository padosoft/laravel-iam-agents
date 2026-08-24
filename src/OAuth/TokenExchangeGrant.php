<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\OAuth;

use DateInterval;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Padosoft\Iam\Agents\Audit\DelegationAudit;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Registry\DbAgentRegistry;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Contracts\Delegation\ActClaim;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationBudgetGuard;
use Padosoft\Iam\Contracts\Delegation\DelegationGrant;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStore;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\OAuth\Token\TokenIssuanceContext;
use Psr\Http\Message\ServerRequestInterface;

/**
 * OAuth 2.0 Token Exchange (RFC 8693) per la delega agli AI agents.
 *
 * L'agente — autenticato con le PROPRIE credenziali (private_key_jwt, mai un secret,
 * mai il token dell'utente come credenziale) — presenta il token dell'utente come
 * `subject_token` e riceve un token DELEGATO: breve, down-scoped, con `sub` = utente,
 * `act` = agente, `pds_dgr` = grant, header `typ` dedicato. Non-refreshable by design:
 * il ri-exchange È il check di freshness della revoca.
 *
 * Pipeline fail-closed (ogni rifiuto è auditato con motivo, stream=delegation):
 *  1. client valido + confidential + grant URN dichiarato (league + ClientRepository);
 *  2. agente registrato per quel client e in stato `active`;
 *  3. subject_token valido (firma/iss/exp via TokenSigner) + SENZA claim `act`
 *     (niente chaining in MVP) + sessione utente ancora VIVA (SessionRegistry);
 *  4. DelegationGrant attiva utente→agente;
 *  5. scope emessi = richiesti ∩ grant ∩ max_scopes agente (vuoto ⇒ invalid_scope);
 *  6. emissione via league (ledger jti incluso → introspection/revoca funzionano).
 *
 * Conformance wire: `actor_token` (multi-hop) e `requested_token_type` ≠ access_token
 * sono rifiutati con errori RFC puliti, così la v2 multi-hop non è breaking.
 */
final class TokenExchangeGrant extends AbstractGrant
{
    /** Hard cap del TTL dei token delegati: oltre, la revoca diventa "fino a scadenza". */
    public const MAX_DELEGATED_TTL = 900;

    public function __construct(
        private readonly TokenSigner $subjectTokens,
        private readonly SessionRegistry $sessions,
        private readonly DbAgentRegistry $agents,
        private readonly DelegationGrantStore $grants,
        private readonly TokenIssuanceContext $issuance,
        private readonly DelegationAudit $audit,
        private readonly string $delegatedTyp = 'delegated+jwt',
    ) {}

    public function getIdentifier(): string
    {
        return ActClaim::GRANT_TYPE_TOKEN_EXCHANGE;
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL,
    ): ResponseTypeInterface {
        $client = $this->validateClient($request);

        if (!$client->isConfidential()) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidClient($request);
        }

        // Conformance RFC 8693 a livello wire: parametri riconosciuti, rifiuti puliti.
        if ($this->getRequestParameter('actor_token', $request) !== null) {
            throw OAuthServerException::invalidRequest('actor_token', 'Delega multi-hop non abilitata (max_delegation_depth=1).');
        }
        $requestedType = $this->getRequestParameter('requested_token_type', $request) ?? ActClaim::TOKEN_TYPE_ACCESS;
        if ($requestedType !== ActClaim::TOKEN_TYPE_ACCESS) {
            throw OAuthServerException::invalidRequest('requested_token_type', 'Solo access_token è emettibile.');
        }
        $subjectTokenType = $this->getRequestParameter('subject_token_type', $request);
        if ($subjectTokenType !== ActClaim::TOKEN_TYPE_ACCESS) {
            throw OAuthServerException::invalidRequest('subject_token_type', 'Solo urn:ietf:params:oauth:token-type:access_token è supportato.');
        }
        $subjectToken = $this->getRequestParameter('subject_token', $request);
        if ($subjectToken === null || $subjectToken === '') {
            throw OAuthServerException::invalidRequest('subject_token');
        }

        // 2) L'agente dietro il client: registrato e ATTIVO (pending/suspended/retired ⇒ deny).
        $agent = $this->agents->findByClientId($client->getIdentifier());
        if ($agent === null) {
            $this->refuse($client->getIdentifier(), null, 'agent_not_registered');
        }
        if ($agent->statusEnum() !== AgentStatus::Active) {
            $this->refuse($agent->id, null, 'agent_not_active');
        }

        // 3) subject_token: firma/iss/exp del NOSTRO issuer; niente act (no chaining MVP);
        //    la sessione dell'utente deve essere ancora viva (hook di revoca, come l'introspection).
        try {
            $claims = $this->subjectTokens->parse($subjectToken);
        } catch (\Throwable) {
            $this->refuse($agent->id, null, 'subject_token_invalid');
        }
        if (array_key_exists(ActClaim::ACT, $claims)) {
            $this->refuse($agent->id, null, 'subject_token_already_delegated');
        }
        $sub = $claims['sub'] ?? null;
        if (!is_string($sub) || $sub === '') {
            $this->refuse($agent->id, null, 'subject_token_without_sub');
        }
        $sid = $claims['sid'] ?? null;
        if (!is_string($sid) || $sid === '') {
            // Un token senza sessione (es. client_credentials) non rappresenta un UTENTE
            // delegante: la delega richiede un umano con sessione revocabile alle spalle.
            $this->refuse($agent->id, $sub, 'subject_token_without_session');
        }
        if (!$this->sessions->active($sid)) {
            $this->refuse($agent->id, $sub, 'subject_session_revoked');
        }

        // 4) La grant attiva utente→agente (consenso non revocato e non scaduto).
        $userRef = new SubjectRef('user', $sub);
        $grant = $this->grants->findActive($userRef, $agent->subject());
        if ($grant === null) {
            $this->refuse($agent->id, $sub, 'no_active_delegation_grant');
        }

        // 4-bis) Budget (v1.1): gli scope limitano l'autorità, il budget l'intensità.
        //    FAIL-CLOSED su due lati: budget dichiarato senza meter bindato ⇒ il vincolo
        //    consentito non è enforceable ⇒ refuse; meter che nega ⇒ refuse (il motivo
        //    dettagliato resta nell'audit, il client vede solo invalid_grant).
        if ($grant->budget !== null) {
            if (!app()->bound(DelegationBudgetGuard::class)) {
                $this->audit->exchange($agent->id, $sub, false, [], $grant->id, 'delegation_budget_unenforceable');

                throw OAuthServerException::invalidGrant();
            }
            $budgetVerdict = app(DelegationBudgetGuard::class)->verdict($grant);
            if (!$budgetVerdict->allowed) {
                $this->audit->exchange($agent->id, $sub, false, [], $grant->id, 'delegation_budget_exhausted: '.$budgetVerdict->reason);

                throw OAuthServerException::invalidGrant();
            }
        }

        // 5) Intersezione degli scope: richiesti ∩ grant ∩ max_scopes (il layer UTENTE
        //    resta al PDP per-request: il token è un upper bound, il PDP la verità).
        $effective = $this->effectiveScopes($this->getRequestParameter('scope', $request), $grant, $agent);
        if ($effective === []) {
            $this->audit->exchange($agent->id, $sub, false, [], $grant->id, 'empty_scope_intersection');

            throw OAuthServerException::invalidScope('(intersezione vuota tra scope richiesti, grant e max_scopes agente)');
        }
        $finalizedScopes = $this->scopeRepository->finalizeScopes(
            $this->validateScopes(implode(self::SCOPE_DELIMITER_STRING, $effective)),
            $this->getIdentifier(),
            $client,
        );

        // 6) Deposita act/pds_dgr/audience/typ nel canale di emissione (P1) e emetti.
        $this->issuance->setActor(['sub' => (string) $agent->subject()], $grant->id);
        $this->issuance->setTyp($this->delegatedTyp);
        $audience = $this->requestedAudience($request);
        if ($audience !== []) {
            $this->issuance->setAudience($audience);
        }

        $accessToken = $this->issueAccessToken($this->cappedTtl($accessTokenTTL), $client, $sub, $finalizedScopes);

        $issuedScopes = array_values(array_map(static fn ($s): string => $s->getIdentifier(), $accessToken->getScopes()));
        $this->issuance->setResponseParams([
            'issued_token_type' => ActClaim::TOKEN_TYPE_ACCESS,
            'scope' => implode(self::SCOPE_DELIMITER_STRING, $issuedScopes),
        ]);

        $this->audit->exchange($agent->id, $sub, true, $issuedScopes, $grant->id);
        $this->getEmitter()->emit(new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $accessToken));
        $responseType->setAccessToken($accessToken);

        return $responseType;
    }

    /**
     * Scope effettivi: richiesti (o, se assenti, quelli della grant) ∩ grant ∩ max_scopes.
     *
     * @return list<string>
     */
    private function effectiveScopes(?string $requestedParam, DelegationGrant $grant, Agent $agent): array
    {
        $maxScopes = array_values(array_filter($agent->max_scopes, 'is_string'));

        $requested = $requestedParam === null || trim($requestedParam) === ''
            ? $grant->scopes
            : array_values(array_filter(explode(self::SCOPE_DELIMITER_STRING, trim($requestedParam)), static fn (string $s): bool => $s !== ''));

        return array_values(array_intersect($requested, $grant->scopes, $maxScopes));
    }

    /**
     * `audience` e `resource` (RFC 8693 §2.1 / RFC 8707): il token delegato vale per la
     * resource richiesta. Parametro singolo in MVP (form-encoding: ripetuti = last-wins).
     *
     * @return list<string>
     */
    private function requestedAudience(ServerRequestInterface $request): array
    {
        $out = [];
        foreach (['audience', 'resource'] as $param) {
            $value = $this->getRequestParameter($param, $request);
            if ($value !== null && $value !== '') {
                $out[] = $value;
            }
        }

        return array_values(array_unique($out));
    }

    /** Applica l'hard cap al TTL configurato: mai oltre MAX_DELEGATED_TTL. */
    private function cappedTtl(DateInterval $configured): DateInterval
    {
        $seconds = (new \DateTimeImmutable('@0'))->add($configured)->getTimestamp();
        $capped = min(max(1, $seconds), self::MAX_DELEGATED_TTL);

        return new DateInterval('PT'.$capped.'S');
    }

    /** Audita il rifiuto e lancia invalid_grant (il motivo dettagliato resta nell'audit, non al client). */
    private function refuse(string $agentId, ?string $sub, string $reason): never
    {
        $this->audit->exchange($agentId, $sub, false, [], null, $reason);

        throw OAuthServerException::invalidGrant();
    }
}
