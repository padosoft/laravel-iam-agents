<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Padosoft\Iam\Agents\Http\Controllers\SelfServiceDelegationsController;

// "Le mie deleghe": lista, consenso (challenge + creazione), revoca one-click.
// Il prefix e il middleware (guard host) sono applicati dal service provider.
Route::get('/', [SelfServiceDelegationsController::class, 'index']);
Route::post('/consent-preview', [SelfServiceDelegationsController::class, 'consentPreview']);
Route::post('/consent-challenge', [SelfServiceDelegationsController::class, 'consentChallenge']);
Route::post('/', [SelfServiceDelegationsController::class, 'store']);
Route::delete('/{grantId}', [SelfServiceDelegationsController::class, 'destroy']);

// "Cosa hanno fatto i miei agenti": la timeline delle ricevute firmate, ognuna
// col proprio JWS, esportabile e verificabile da chiunque col JWKS pubblico.
Route::get('/receipts', [SelfServiceDelegationsController::class, 'receipts']);

// JIT elevation (v1.1): il delegante approva (RI-consenso step-up, due passi) o nega
// (one-click) le richieste di scope aggiuntivi. Le pending sono nella GET / (index).
Route::post('/elevations/{elevationId}/consent-challenge', [SelfServiceDelegationsController::class, 'elevationChallenge']);
Route::post('/elevations/{elevationId}/approve', [SelfServiceDelegationsController::class, 'elevationApprove']);
Route::post('/elevations/{elevationId}/deny', [SelfServiceDelegationsController::class, 'elevationDeny']);
