<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Support;

use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Identity\SessionRef;

/** Default fail-closed: nessuna sessione risolta ⇒ il consenso nativo rifiuta. */
final class NullDelegationSessionResolver implements DelegationSessionResolver
{
    public function resolve(Request $request): ?SessionRef
    {
        return null;
    }
}
