<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Events;

use Padosoft\Iam\Agents\Models\DelegationFreezeModel;

/**
 * Il quorum è stato raggiunto e la delega è ripartita. `approvals` è il numero di
 * admin distinti che hanno approvato — il fatto che rende l'evento diverso da un
 * semplice "unfrozen": ripartire è una decisione collettiva, e l'evento lo dice.
 */
final readonly class DelegationUnfrozen
{
    public function __construct(
        public DelegationFreezeModel $freeze,
        public int $approvals,
    ) {}
}
