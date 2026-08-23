<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Padosoft\Iam\Agents\Http\Controllers\AgentRegistrationController;
use Padosoft\Iam\Agents\Http\Controllers\DiscoveryController;

// Discovery agentic (sempre attiva quando il modulo è enabled: è metadata pubblico).
Route::get('/.well-known/agent-auth.json', [DiscoveryController::class, 'agentAuth']);
Route::get('/AUTH.md', [DiscoveryController::class, 'authMd']);

// Registrazione agentic (DCR RFC 7591 gated): OFF di default, rate-limited, e
// SEMPRE in stato pending — Active solo con approvazione umana in admin.
$rateLimit = config('iam-agents.registration.rate_limit', '10,1');
Route::post('/oauth/register', [AgentRegistrationController::class, 'register'])
    ->middleware('throttle:'.(is_string($rateLimit) ? $rateLimit : '10,1'));
