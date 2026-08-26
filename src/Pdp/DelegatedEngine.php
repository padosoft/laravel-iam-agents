<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Pdp;

use Illuminate\Support\Str;
use Padosoft\Iam\Agents\Freeze\DelegationFreezeService;
use Padosoft\Iam\Agents\Freeze\DelegationFrozenException;
use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Contracts\Delegation\AgentRegistry;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Delegation\DelegatedAuthorizationEngine;
use Padosoft\Iam\Contracts\Delegation\DelegationChain;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStore;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * PDP delegato: decorator dell'engine nativo che applica l'INTERSECTION RULE.
 *
 * autorità effettiva = decision(utente) ∧ decision(agente) [∧ ogni hop] ∧ grant attiva.
 * MAI l'unione. Deny-overrides composto: un deny esplicito su QUALUNQUE layer nega;
 * assenza di allow su un layer nega (fail-closed). Agente ignoto/pending/sospeso/
 * retired ⇒ deny `agent_not_active` senza nemmeno interrogare l'engine.
 *
 * La decisione cita ENTRAMBI i soggetti: `sub_decisions` porta i decision id dei due
 * passi, così un auditor rigioca separatamente perché il lato utente e il lato agente
 * hanno permesso. L'engine interno resta INTATTO per i check single-subject.
 */
final class DelegatedEngine implements DelegatedAuthorizationEngine
{
    public function __construct(
        private readonly AuthorizationEngine $inner,
        private readonly AgentRegistry $agents,
        private readonly DelegationGrantStore $grants,
        private readonly ?DelegationFreezeService $freeze = null,
    ) {}

    /**
     * @param  array<string, mixed>  $query
     * @return array<string, mixed>
     */
    public function check(array $query): array
    {
        return $this->inner->check($query);
    }

    public function listSubjects(string $relation, string $objectType, string $objectId): iterable
    {
        return $this->inner->listSubjects($relation, $objectType, $objectId);
    }

    public function listResources(SubjectRef $subject, string $relation): iterable
    {
        return $this->inner->listResources($subject, $relation);
    }

    /**
     * @param  array<string, mixed>  $query  stessa shape di check(); chiave opzionale
     *                                       `delegation_grant_id` (claim pds_dgr) per il check di revoca mirato
     * @return array<string, mixed>
     */
    public function checkDelegated(SubjectRef $subject, DelegationChain $chain, array $query): array
    {
        $decisionId = 'dec_'.Str::ulid()->toBase32();

        // Kill switch, PRIMO di tutto. È il punto che rende il freeze un vero kill
        // switch e non solo uno stop alle nuove emissioni: i token delegati già in
        // circolazione restano validi fino alla scadenza (5 minuti), ma da qui in
        // poi non decidono più nulla. Fermare l'emissione e basta lascerebbe una
        // finestra di TTL in cui la flotta "congelata" continua ad agire.
        if ($this->freeze !== null) {
            try {
                $this->freeze->assertNotFrozen($chain->current()->subject->id);
            } catch (DelegationFrozenException $e) {
                return $this->deny($decisionId, $chain, $e->reason);
            }
        }

        // Layer agente: ogni hop della catena deve essere un agente ATTIVO. Fail-closed
        // PRIMA di toccare l'engine: un agente ignoto non produce nemmeno una query.
        foreach ($chain->actors as $actor) {
            $descriptor = $this->agents->find($actor->subject);
            if ($descriptor === null || $descriptor->status !== AgentStatus::Active) {
                return $this->deny($decisionId, $chain, 'agent_not_active');
            }
        }

        // Revoca mirata: se il token porta pds_dgr, la grant deve essere ANCORA usabile
        // e coerente con la coppia (utente, attore corrente) del token.
        $grantId = $query['delegation_grant_id'] ?? null;
        unset($query['delegation_grant_id']);
        if (is_string($grantId) && $grantId !== '') {
            $grant = $this->grants->find($grantId);
            if ($grant === null
                || !$grant->isUsableAt(new \DateTimeImmutable)
                || (string) $grant->user !== (string) $subject
                || (string) $grant->agent !== (string) $chain->current()->subject
            ) {
                return $this->deny($decisionId, $chain, 'delegation_grant_not_active');
            }
        }

        // Intersezione: il check dell'UTENTE e il check dell'AGENTE (stesso engine,
        // stessa query, soggetti diversi). Entrambi devono permettere.
        $subjectDecision = $this->inner->check($this->queryFor($query, $subject));
        $actorDecision = $this->inner->check($this->queryFor($query, $chain->current()->subject));

        $allowed = ($subjectDecision['allowed'] ?? false) === true
            && ($actorDecision['allowed'] ?? false) === true;

        return [
            'allowed' => $allowed,
            'decision_id' => $decisionId,
            'actors' => array_map(strval(...), $chain->actors),
            'sub_decisions' => [
                'subject' => $subjectDecision['decision_id'] ?? null,
                'actor' => $actorDecision['decision_id'] ?? null,
            ],
            'policy_version' => $subjectDecision['policy_version'] ?? 0,
            'requires_step_up' => ($subjectDecision['requires_step_up'] ?? false) === true
                || ($actorDecision['requires_step_up'] ?? false) === true,
        ];
    }

    /**
     * @param  array<string, mixed>  $query
     * @return array<string, mixed>
     */
    private function queryFor(array $query, SubjectRef $subject): array
    {
        $query['subject'] = ['type' => $subject->type, 'id' => $subject->id];

        return $query;
    }

    /**
     * @return array<string, mixed>
     */
    private function deny(string $decisionId, DelegationChain $chain, string $reason): array
    {
        return [
            'allowed' => false,
            'decision_id' => $decisionId,
            'actors' => array_map(strval(...), $chain->actors),
            'sub_decisions' => ['subject' => null, 'actor' => null],
            'reason' => $reason,
        ];
    }
}
