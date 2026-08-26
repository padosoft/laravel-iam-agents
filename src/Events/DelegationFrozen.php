<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Events;

use Padosoft\Iam\Agents\Models\DelegationFreezeModel;

/**
 * La delega è stata congelata. Un solo admin l'ha deciso, e da questo istante
 * nessun token delegato viene emesso e nessuna decisione delegata passa nello
 * scope coperto.
 *
 * Consumer naturali: `laravel-ai-act-compliance` (fermare una flotta di agenti è
 * un atto di oversight umano, art. 14) e le superfici admin, che devono mostrare
 * lo stato "congelato" senza fare polling.
 */
final readonly class DelegationFrozen
{
    public function __construct(public DelegationFreezeModel $freeze) {}
}
