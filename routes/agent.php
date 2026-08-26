<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Padosoft\Iam\Agents\Http\Controllers\AgentReceiptsController;

// Superficie dell'AGENTE: autenticata dal token delegato stesso (Bearer), non da
// una sessione e non da una chiave d'app. Il throttle è per-IP e volutamente
// stretto: coniare ricevute è economico e un agente in loop non deve poter
// riempire la tabella dell'evidenza.
Route::post('iam/agent/receipts', [AgentReceiptsController::class, 'store'])
    ->middleware('throttle:'.config('iam-agents.receipts.rate_limit', '120,1'));
