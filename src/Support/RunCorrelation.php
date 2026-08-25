<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Support;

use Illuminate\Support\Facades\Context;
use Laravel\Ai\Events\AgentFailed;
use Laravel\Ai\Events\AgentPrompted;
use Laravel\Ai\Events\StartingStep;
use Laravel\Ai\Gateway\ParentInvocation;

/**
 * Stampa l'id del run AI sul contesto di delega ambientale.
 *
 * Il §10 del design promette che OGNI log e audit record di qualunque package
 * porti "chi ha fatto cosa, per conto di chi" senza conoscere la delega: il
 * middleware idrata `iam_delegation` nel Laravel Context all'ingresso, e da lì si
 * propaga da solo — anche nei job accodati.
 *
 * Mancava però la chiave che unisce quel contesto al *lavoro*: fino a laravel/ai
 * 0.11 un record di finops o di eval si correlava al run di un agente solo per
 * approssimazione temporale. Ora l'SDK propaga un `invocationId` su ogni evento
 * di step e di tool, e quando un agente è usato come tool del run padre conosce
 * anche l'hop precedente — la stessa relazione della catena `act`, vista dal
 * runtime invece che dal token.
 *
 * Non emette nulla di suo: arricchisce il contesto che esiste già. Su un'app
 * senza delega attiva (nessun `iam_delegation` idratato) è un no-op, così un run
 * non delegato non si inventa un contesto di delega vuoto.
 */
final class RunCorrelation
{
    /** Chiave del Laravel Context idratata da `IamCanDelegated` (iam-client). */
    public const CONTEXT_KEY = 'iam_delegation';

    public function handleStartingStep(StartingStep $event): void
    {
        $context = Context::get(self::CONTEXT_KEY);

        if (! is_array($context)) {
            return;
        }

        // Già stampato da uno step precedente dello stesso run: non riscrivere.
        if (($context['invocation_id'] ?? null) === $event->invocationId) {
            return;
        }

        [$parentInvocationId, $parentToolInvocationId] = ParentInvocation::current();

        Context::add(self::CONTEXT_KEY, array_filter([
            ...$context,
            'invocation_id' => $event->invocationId,
            'parent_invocation_id' => $parentInvocationId,
            'parent_tool_invocation_id' => $parentInvocationId === null ? null : $parentToolInvocationId,
        ], static fn ($value) => $value !== null));
    }

    /**
     * Il run è finito: l'id smette di valere per ciò che il processo fa dopo.
     *
     * Lasciarlo attaccato è peggio che non averlo mai messo — ogni log successivo
     * verrebbe attribuito a un run che non sta più girando, e le query pivot per
     * invocation nei pannelli admin conterebbero lavoro che non è suo.
     */
    public function handleRunFinished(AgentPrompted|AgentFailed $event): void
    {
        $context = Context::get(self::CONTEXT_KEY);

        if (! is_array($context) || ($context['invocation_id'] ?? null) !== $event->invocationId) {
            return;
        }

        unset($context['invocation_id'], $context['parent_invocation_id'], $context['parent_tool_invocation_id']);

        Context::add(self::CONTEXT_KEY, $context);
    }
}
