<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Padosoft\Iam\Agents\Http\Controllers\Admin\AgentsController;
use Padosoft\Iam\Agents\Http\Controllers\Admin\DelegatedDecisionsController;
use Padosoft\Iam\Agents\Http\Controllers\Admin\DelegationFreezesController;
use Padosoft\Iam\Agents\Http\Controllers\Admin\DelegationGrantsController;

// Admin API del modulo agents: stesso stack del server (iam.admin_auth/iam.can/
// iam.idempotency applicati dal provider e per-route). Permission slug dedicati.
Route::get('agents', [AgentsController::class, 'index'])->middleware('iam.can:iam:agents.manage');
Route::post('agents', [AgentsController::class, 'store'])->middleware('iam.can:iam:agents.manage');
Route::get('agents/{id}', [AgentsController::class, 'show'])->middleware('iam.can:iam:agents.manage');
Route::post('agents/{id}/approve', [AgentsController::class, 'approve'])->middleware('iam.can:iam:agents.manage');
Route::post('agents/{id}/suspend', [AgentsController::class, 'suspend'])->middleware('iam.can:iam:agents.manage');
Route::post('agents/{id}/retire', [AgentsController::class, 'retire'])->middleware('iam.can:iam:agents.manage');

Route::get('delegation-grants', [DelegationGrantsController::class, 'index'])->middleware('iam.can:iam:delegations.manage');
Route::post('delegation-grants/{id}/revoke', [DelegationGrantsController::class, 'revoke'])->middleware('iam.can:iam:delegations.manage');

// Kill switch asimmetrico. Congelare e scongelare sono due PERMESSI diversi, non
// solo due quorum diversi: fermare la flotta deve essere alla portata di chiunque
// amministri la delega, farla ripartire no.
Route::get('delegation-freezes', [DelegationFreezesController::class, 'index'])->middleware('iam.can:iam:delegations.manage');
Route::post('delegation-freezes', [DelegationFreezesController::class, 'store'])->middleware('iam.can:iam:delegations.manage');
Route::get('delegation-freezes/{id}', [DelegationFreezesController::class, 'show'])->middleware('iam.can:iam:delegations.manage');
Route::post('delegation-freezes/{id}/approve-lift', [DelegationFreezesController::class, 'approveLift'])->middleware('iam.can:iam:delegations.unfreeze');

// Decisioni delegate per i PEP: stessa permission del check single-subject del server.
Route::post('decisions/check-delegated', [DelegatedDecisionsController::class, 'check'])->middleware('iam.can:iam:decisions.check');
