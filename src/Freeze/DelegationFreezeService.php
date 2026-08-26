<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Freeze;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Padosoft\Iam\Agents\Audit\DelegationAudit;
use Padosoft\Iam\Agents\Events\DelegationFrozen;
use Padosoft\Iam\Agents\Events\DelegationUnfrozen;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationFreezeApprovalModel;
use Padosoft\Iam\Agents\Models\DelegationFreezeModel;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Il kill switch ASIMMETRICO della delega: **uno solo per fermare, molti per
 * ripartire.**
 *
 * L'asimmetria non è un vezzo. In un incidente l'esitazione costa più di un falso
 * positivo: chiunque amministri la delega deve poter tirare la leva da solo, subito,
 * senza cercare un collega alle tre di notte. Ripartire è l'operazione opposta —
 * è esattamente il momento in cui un attaccante (o un operatore che vuole solo far
 * sparire l'allarme) ha interesse a essere l'unico decisore — e quindi è l'unico
 * lato su cui mettere attrito.
 *
 * L'asimmetria è su due assi indipendenti:
 *
 *  - **quorum**: congelare = 1 admin; scongelare = `lift_quorum` admin DISTINTI
 *    (unique `(freeze_id, approver)` a livello di schema, non solo di codice);
 *  - **permesso**: congelare richiede `iam:delegations.manage`, approvare la
 *    rimozione richiede `iam:delegations.unfreeze` — un permesso a sé, che si
 *    concede a meno persone di quante possano fermare la flotta.
 *
 * Tre decisioni portanti, tutte contro-intuitive abbastanza da valere una riga:
 *
 *  1. **Il quorum è fotografato al freeze**, non riletto allo sblocco. Altrimenti
 *     chi può modificare la config lo porta a 1 e scongela da solo, e il controllo
 *     protegge esattamente nessuno.
 *  2. **Chi ha congelato può approvare come chiunque altro.** Escluderlo non
 *     aggiunge sicurezza — l'attaccante che vuole scongelare non è quello che ha
 *     congelato — e toglie una firma proprio a chi sta gestendo l'incidente. Il
 *     controllo delle due paia d'occhi viene da `lift_quorum >= 2`, non
 *     dall'esclusione.
 *  3. **La revoca non è mai bloccata da un freeze.** Congelare significa fermare
 *     ciò che gli agenti possono FARE; se bloccasse anche revocare grant o
 *     sospendere agenti, il kill switch impedirebbe la risposta all'incidente che
 *     lo ha causato.
 *
 * E una nota di costo, dichiarata perché è una scelta e non una dimenticanza: il
 * controllo del freeze **non è cachato**. Un kill switch che impiega trenta secondi
 * a uccidere non è un kill switch. È una lookup indicizzata su una tabella minuscola,
 * più economica dei due check PDP che precede.
 */
final class DelegationFreezeService
{
    /**
     * Esito di `Schema::hasTable`, memorizzato per istanza (il servizio è un
     * singleton). Distinguere "modulo aggiornato, migrazione non ancora girata"
     * da "non riesco a leggere lo stato" evita che un deploy fra il codice nuovo
     * e `php artisan migrate` neghi ogni delega per qualche minuto.
     */
    private ?bool $installed = null;

    public function __construct(private readonly DelegationAudit $audit) {}

    /**
     * Congela. Un solo admin, effetto immediato, nessuna approvazione richiesta.
     *
     * Un freeze già attivo che copre lo STESSO scope non viene duplicato: viene
     * restituito quello esistente. Congelare due volte durante un incidente è un
     * riflesso normale e non deve creare due freeze da sbloccare separatamente.
     */
    public function freeze(FreezeScope $scope, ?string $scopeId, string $reason, SubjectRef $by): DelegationFreezeModel
    {
        $reason = trim($reason);

        if ($reason === '') {
            throw new FreezeException('Un freeze richiede un motivo: senza, nessuno sa quando toglierlo.');
        }

        if ($scope->requiresScopeId() && ($scopeId === null || trim($scopeId) === '')) {
            throw new FreezeException("Il freeze di scope [{$scope->value}] richiede l'id del target.");
        }

        $scopeId = $scope->requiresScopeId() ? trim((string) $scopeId) : null;

        $existing = DelegationFreezeModel::query()
            ->whereNull('lifted_at')
            ->where('scope', $scope->value)
            ->where(fn ($q) => $scopeId === null ? $q->whereNull('scope_id') : $q->where('scope_id', $scopeId))
            ->first();

        if ($existing !== null) {
            return $existing;
        }

        $freeze = new DelegationFreezeModel([
            'id' => DelegationFreezeModel::newId(),
            'scope' => $scope->value,
            'scope_id' => $scopeId,
            'reason' => $reason,
            'frozen_by' => (string) $by,
            'frozen_at' => now(),
            'required_quorum' => self::configuredQuorum(),
        ]);
        $freeze->save();

        $this->audit->freezeApplied($freeze);
        event(new DelegationFrozen($freeze));

        return $freeze;
    }

    /**
     * Registra UNA approvazione alla rimozione e, se il quorum è raggiunto,
     * scongela nella stessa transazione.
     *
     * Il lock sulla riga del freeze tiene fino alla scrittura di `lifted_at`, così
     * due approvazioni finali concorrenti non possono entrambe vedere il quorum
     * incompleto e poi entrambe sbloccare — stessa disciplina di ogni consumo
     * single-use di questo ecosistema.
     */
    public function approveLift(string $freezeId, SubjectRef $approver, ?string $note = null): LiftOutcome
    {
        return DB::transaction(function () use ($freezeId, $approver, $note): LiftOutcome {
            $freeze = DelegationFreezeModel::query()->lockForUpdate()->find($freezeId);

            if ($freeze === null) {
                throw new FreezeException("Freeze [{$freezeId}] inesistente.");
            }

            if (!$freeze->isActive()) {
                throw new FreezeException("Freeze [{$freezeId}] già rimosso.");
            }

            $already = DelegationFreezeApprovalModel::query()
                ->where('freeze_id', $freeze->id)
                ->where('approver', (string) $approver)
                ->exists();

            if (!$already) {
                DelegationFreezeApprovalModel::query()->create([
                    'freeze_id' => $freeze->id,
                    'approver' => (string) $approver,
                    'note' => $note,
                    'approved_at' => now(),
                ]);
            }

            $collected = DelegationFreezeApprovalModel::query()->where('freeze_id', $freeze->id)->count();

            $this->audit->freezeLiftApproved($freeze, $approver, $collected, $already);

            if ($collected < $freeze->required_quorum) {
                return new LiftOutcome(false, $collected, $freeze->required_quorum, $already);
            }

            // `lifted_by` è chi ha COMPLETATO il quorum; l'elenco integrale degli
            // approvatori resta nelle righe di approvazione e nell'audit.
            $freeze->lifted_at = now();
            $freeze->lifted_by = (string) $approver;
            $freeze->save();

            $this->audit->freezeLifted($freeze, $collected);
            event(new DelegationUnfrozen($freeze, $collected));

            return new LiftOutcome(true, $collected, $freeze->required_quorum, $already);
        });
    }

    /**
     * Il check della hot path: c'è un freeze attivo che copre questo agente?
     *
     * Restituisce il freeze PIÙ AMPIO fra quelli che coprono il target: davanti a
     * un freeze globale e uno del singolo agente, quello globale è la risposta più
     * utile per chi legge il rifiuto.
     *
     * `$organizationId` è opzionale perché il PDP delegato non ce l'ha: il claim
     * `act` porta l'agente, non la sua organizzazione. Invece di allargare il
     * contratto `AgentDescriptor` per un dato che serve solo qui, l'organizzazione
     * viene risolta SOLO quando esiste davvero un freeze di scope `organization` —
     * cioè quasi mai. Il caso comune resta una sola query.
     *
     * @throws DelegationFrozenException quando lo stato non è leggibile: per un kill
     *                                   switch "non ho potuto verificare" non è "va bene"
     */
    public function activeFor(?string $agentId = null, ?string $organizationId = null): ?DelegationFreezeModel
    {
        if (!$this->installed()) {
            return null;
        }

        try {
            /** @var list<DelegationFreezeModel> $freezes */
            $freezes = DelegationFreezeModel::query()
                ->whereNull('lifted_at')
                ->where(function ($q) use ($agentId): void {
                    $q->where('scope', FreezeScope::Global->value)
                        ->orWhere('scope', FreezeScope::Organization->value);

                    if ($agentId !== null && $agentId !== '') {
                        $q->orWhere(fn ($a) => $a->where('scope', FreezeScope::Agent->value)->where('scope_id', $agentId));
                    }
                })
                ->get()
                ->all();
        } catch (QueryException) {
            throw DelegationFrozenException::stateUnavailable();
        }

        if ($freezes === []) {
            return null;
        }

        $organizationId = $this->resolveOrganization($freezes, $agentId, $organizationId);

        $freezes = array_values(array_filter(
            $freezes,
            static fn (DelegationFreezeModel $f): bool => $f->scope !== FreezeScope::Organization->value
                || ($organizationId !== null && $organizationId !== '' && $f->scope_id === $organizationId),
        ));

        if ($freezes === []) {
            return null;
        }

        $rank = [FreezeScope::Global->value => 0, FreezeScope::Organization->value => 1, FreezeScope::Agent->value => 2];
        usort($freezes, static fn (DelegationFreezeModel $a, DelegationFreezeModel $b): int => ($rank[$a->scope] ?? 9) <=> ($rank[$b->scope] ?? 9));

        return $freezes[0];
    }

    /**
     * L'organizzazione dell'agente, letta SOLO se serve davvero: cioè se fra i
     * freeze attivi ce n'è almeno uno di scope `organization` e il chiamante non
     * l'ha già passata.
     *
     * @param  list<DelegationFreezeModel>  $freezes
     */
    private function resolveOrganization(array $freezes, ?string $agentId, ?string $organizationId): ?string
    {
        if ($organizationId !== null && $organizationId !== '') {
            return $organizationId;
        }

        if ($agentId === null || $agentId === '') {
            return null;
        }

        $needsOrganization = array_filter(
            $freezes,
            static fn (DelegationFreezeModel $f): bool => $f->scope === FreezeScope::Organization->value,
        ) !== [];

        if (!$needsOrganization) {
            return null;
        }

        try {
            $value = Agent::query()->whereKey($agentId)->value('organization_id');
        } catch (QueryException) {
            throw DelegationFrozenException::stateUnavailable();
        }

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @throws DelegationFrozenException
     */
    public function assertNotFrozen(?string $agentId = null, ?string $organizationId = null): void
    {
        $freeze = $this->activeFor($agentId, $organizationId);

        if ($freeze !== null) {
            throw DelegationFrozenException::frozen($freeze->id, $freeze->scope, $freeze->reason);
        }
    }

    /**
     * Quorum configurato, con un minimo di 1.
     *
     * `1` è ammesso e significa "nessun quorum": resta comunque l'asimmetria di
     * PERMESSO (fermare e ripartire sono due permessi diversi). Un team di due
     * persone che mettesse 3 non potrebbe più ripartire, quindi il valore non è
     * imposto — ma il default è 2, perché il default deve essere il controllo,
     * non la comodità.
     */
    public static function configuredQuorum(): int
    {
        $quorum = config('iam-agents.kill_switch.lift_quorum', 2);

        return max(1, is_numeric($quorum) ? (int) $quorum : 2);
    }

    private function installed(): bool
    {
        return $this->installed ??= Schema::hasTable('iam_delegation_freezes');
    }
}
