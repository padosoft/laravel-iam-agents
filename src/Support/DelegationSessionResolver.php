<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Support;

use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Identity\SessionRef;

/**
 * Risolve la sessione IAM (sid) dell'utente corrente per il flusso di consenso.
 * È dell'app host sapere DOVE vive il sid (sessione Laravel, cookie, claim):
 * si configura in `iam-agents.consent.session_resolver` (FQCN). Il default
 * NullDelegationSessionResolver ritorna null ⇒ il consenso nativo rifiuta
 * (fail-closed) finché l'host non lo cabla.
 */
interface DelegationSessionResolver
{
    public function resolve(Request $request): ?SessionRef;
}
