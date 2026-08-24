<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Padosoft\Iam\Agents\Http\Controllers\SelfServiceDelegationsController;

// "Le mie deleghe": lista, consenso (challenge + creazione), revoca one-click.
// Il prefix e il middleware (guard host) sono applicati dal service provider.
Route::get('/', [SelfServiceDelegationsController::class, 'index']);
Route::post('/consent-challenge', [SelfServiceDelegationsController::class, 'consentChallenge']);
Route::post('/', [SelfServiceDelegationsController::class, 'store']);
Route::delete('/{grantId}', [SelfServiceDelegationsController::class, 'destroy']);
