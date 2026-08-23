<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Consent;

/**
 * Consenso non verificabile: challenge assente/scaduta/già usata, binding dei parametri
 * divergente, AAL insufficiente, o nessun verifier configurato. SEMPRE un rifiuto della
 * creazione grant (fail-closed) — mai una degradazione.
 */
final class ConsentFailedException extends \RuntimeException {}
