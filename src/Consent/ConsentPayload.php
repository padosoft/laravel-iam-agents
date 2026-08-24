<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Consent;

/**
 * I parametri del consenso che l'utente sta approvando: QUALE agente, QUALI scope,
 * per QUANTO, a QUALE scopo. Il binding hash canonico (JSON a chiavi fisse, scope
 * ordinati) è l'analogo del dynamic linking PSD2: parametri cambiati dopo la
 * schermata ⇒ hash diverso ⇒ conferma invalida.
 */
final readonly class ConsentPayload
{
    /** @var list<string> */
    public array $scopes;

    /**
     * @param  list<string>  $scopes
     */
    public function __construct(
        public string $agentId,
        array $scopes,
        public int $ttlSeconds,
        public string $purpose,
    ) {
        if ($this->agentId === '' || $this->purpose === '' || $this->ttlSeconds <= 0) {
            throw new \InvalidArgumentException('ConsentPayload incompleto (agentId/purpose/ttl).');
        }
        $clean = array_values(array_unique(array_filter($scopes, static fn (string $s): bool => $s !== '')));
        if ($clean === []) {
            throw new \InvalidArgumentException('ConsentPayload senza scope: una delega vuota non è consentibile.');
        }
        sort($clean);
        $this->scopes = $clean;
    }

    /** Canonicalizzazione anti delimiter-injection: JSON a chiavi fisse, mai concatenazione. */
    public function canonical(): string
    {
        return json_encode([
            'agent' => $this->agentId,
            'scopes' => $this->scopes,
            'ttl' => $this->ttlSeconds,
            'purpose' => $this->purpose,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    public function bindingHash(): string
    {
        return hash('sha256', $this->canonical());
    }
}
