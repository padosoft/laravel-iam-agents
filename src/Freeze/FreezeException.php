<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Freeze;

use RuntimeException;

/**
 * Errore di USO del kill switch (motivo mancante, freeze inesistente o già
 * rimosso) — distinto da {@see DelegationFrozenException}, che è l'effetto del
 * kill switch su chi prova ad agire. Confonderli renderebbe indistinguibile
 * "hai sbagliato la chiamata" da "la delega è ferma".
 */
final class FreezeException extends RuntimeException {}
