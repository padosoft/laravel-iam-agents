<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Consent;

use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Contracts\Delegation\AgentRegistry;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Autorità EFFETTIVA di una delega, prima che l'utente la conceda.
 *
 * Una schermata di consenso che elenca `orders:read` chiede all'utente di
 * approvare un nome, non un effetto: nessuno sa quali ordini siano, e "quanti"
 * è esattamente la domanda che conta. Qui si usa il reverse-index del PDP
 * (`listResources`) sui DUE soggetti e si mostra l'INTERSEZIONE — le risorse
 * concrete che l'agente potrebbe davvero toccare per conto di quell'utente.
 *
 * Tre proprietà che questa classe deve mantenere:
 *
 * 1. **Intersezione, mai unione.** Stesso invariante del PDP: l'agente non può
 *    raggiungere ciò che l'utente non raggiunge, e viceversa.
 * 2. **Il troncamento si DICHIARA.** Un utente con diecimila ordini non può
 *    vederli tutti, ma un preview che ne mostra dieci senza dire che ce ne sono
 *    altre 9990 fa sembrare piccola una delega enorme: sarebbe peggio che non
 *    mostrarlo affatto. `truncated` e `total` sono parte del contratto.
 * 3. **Il preview NON è un'autorizzazione.** È una fotografia scattata adesso;
 *    la verità resta il PDP a ogni richiesta. Se i permessi cambiano tra il
 *    preview e l'uso, è il PDP a decidere — non questa lista.
 */
final readonly class ConsentPreview
{
    public function __construct(
        private AuthorizationEngine $engine,
        private AgentRegistry $agents,
        private int $perRelationLimit = 25,
    ) {}

    /**
     * @param  list<string>  $relations  relazioni ReBAC da ispezionare
     * @return array{agent_status: string, relations: list<array{relation: string, resources: list<string>, total: int, truncated: bool}>}
     */
    public function forGrant(SubjectRef $user, SubjectRef $agent, array $relations): array
    {
        $descriptor = $this->agents->find($agent);

        // Un agente non attivo non può ricevere nulla: mostrare risorse accanto a
        // un agente sospeso suggerirebbe un accesso che non avverrebbe comunque.
        if ($descriptor === null || $descriptor->status !== AgentStatus::Active) {
            return [
                'agent_status' => $descriptor?->status->value ?? 'unknown',
                'relations' => [],
            ];
        }

        $out = [];
        foreach (array_values(array_unique($relations)) as $relation) {
            if (!is_string($relation) || $relation === '') {
                continue;
            }

            $userReach = $this->reach($user, $relation);
            $agentReach = $this->reach($agent, $relation);

            // array_intersect_key su chiavi = identificatori: O(n) invece del
            // confronto quadratico che array_intersect farebbe su liste lunghe.
            $effective = array_keys(array_intersect_key($userReach, $agentReach));
            sort($effective);

            $out[] = [
                'relation' => $relation,
                'resources' => array_slice($effective, 0, $this->perRelationLimit),
                'total' => count($effective),
                'truncated' => count($effective) > $this->perRelationLimit,
            ];
        }

        return ['agent_status' => AgentStatus::Active->value, 'relations' => $out];
    }

    /**
     * Risorse raggiungibili, come mappa "type:id" => true per l'intersezione.
     *
     * Il reverse-index del PDP produce `array{type: string, id: string}`: la chiave
     * composta e' quella che identifica davvero una risorsa, perche' due tipi diversi
     * possono condividere lo stesso id e non sono la stessa cosa.
     *
     * @return array<string, true>
     */
    private function reach(SubjectRef $subject, string $relation): array
    {
        $map = [];
        foreach ($this->engine->listResources($subject, $relation) as $resource) {
            $type = $resource['type'] ?? '';
            $id = $resource['id'] ?? '';
            if ($type !== '' && $id !== '') {
                $map[$type.':'.$id] = true;
            }
        }

        return $map;
    }
}
