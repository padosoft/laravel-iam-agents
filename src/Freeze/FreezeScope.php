<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Freeze;

/**
 * Quanto copre un freeze.
 *
 * Tre livelli e non uno solo, perché in un incidente la domanda vera è *quanto*
 * spegnere: un agente che si comporta male non deve costare l'intera flotta, e
 * una compromissione dell'issuer non si ferma agente per agente.
 */
enum FreezeScope: string
{
    /** Tutta la delega, ovunque. L'interruttore generale. */
    case Global = 'global';

    /** Tutta la delega degli agenti di una organizzazione. */
    case Organization = 'organization';

    /** Un singolo agente. */
    case Agent = 'agent';

    public function requiresScopeId(): bool
    {
        return $this !== self::Global;
    }
}
