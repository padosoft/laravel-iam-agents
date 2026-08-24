<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Elevation;

/**
 * Fallimento del flusso di JIT elevation (richiesta non valida, grant non
 * usabile, scope fuori ceiling, richiesta scaduta/decisa). Fail-closed: il
 * chiamante NON deve mai interpretare l'assenza dell'eccezione come elevazione
 * avvenuta — solo lo stato `approved` sulla riga lo è.
 */
final class ElevationException extends \RuntimeException {}
