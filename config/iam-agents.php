<?php

declare(strict_types=1);

// Config del modulo agents (delega RFC 8693). Ogni default è fail-closed: il modulo
// installato ma non configurato non concede nulla.
return [

    // Interruttore del modulo. Anche il server (config('iam.agents.enabled')) può gatearlo:
    // pattern config-flag + 409 come per iam-directory.
    'enabled' => env('IAM_AGENTS_ENABLED', true),

    'tokens' => [
        // TTL dei token delegati (secondi). Corti BY DESIGN: il ri-exchange È il check di
        // freshness della revoca. Hard cap 900 applicato nel codice: alzarlo oltre converte
        // silenziosamente la revoca da "al prossimo check" a "fino a scadenza".
        'delegated_ttl' => env('IAM_AGENTS_DELEGATED_TOKEN_TTL', 300),

        // Header `typ` dei token delegati (igiene di spec; la difesa primaria è l'introspection).
        'typ' => 'delegated+jwt',
    ],

    'grants' => [
        // Durata massima di una DelegationGrant (giorni). Il consenso non è eterno.
        'max_ttl_days' => env('IAM_AGENTS_GRANT_MAX_TTL_DAYS', 30),
    ],

    // Profondità massima della catena di delega. 1 = niente multi-hop (MVP);
    // `actor_token` viene rifiutato con invalid_request pulito (conformance wire RFC 8693).
    'max_delegation_depth' => 1,

    'consent' => [
        // Purpose step-up del consenso. Kebab-case OBBLIGATORIO: i punti sono separatori
        // di path config in rebel-step-up e il validator CI salta le chiavi annidate.
        'purpose' => 'iam-delegation-grant',

        // AAL minimo del consenso (NIST 800-63B). Esplicito, mai implicito.
        'required_aal' => 'aal2',

        // FQCN del ConsentVerifier. null → NullConsentVerifier (fail-closed: NESSUNA grant
        // creabile finché non configuri un verifier reale). Opzioni del modulo:
        // - \Padosoft\Iam\Agents\Consent\IamNativeConsentVerifier::class (step-up nativo IAM,
        //   single-use reale, dynamic-linking emulato module-side via hash parametri)
        // - adapter rebel-step-up (dynamic linking PSD2-grade) quando il pacchetto è installato.
        'verifier' => null,

        // FQCN del DelegationSessionResolver: dice al modulo DOVE vive il sid IAM
        // dell'utente corrente (sessione Laravel, cookie, claim — lo sa l'app host).
        // null → NullDelegationSessionResolver (fail-closed: consenso nativo rifiuta).
        'session_resolver' => null,
    ],

    'registration' => [
        // Registrazione agentic (DCR RFC 7591 gated + auth.md/ID-JAG). OFF di default.
        // Le registrazioni atterrano SEMPRE in stato `pending`: Active solo con
        // approvazione umana in admin. Mai auto-provisioning.
        'enabled' => env('IAM_AGENTS_REGISTRATION_ENABLED', false),

        // Rate limit dell'endpoint di registrazione (throttle Laravel "tentativi,minuti").
        'rate_limit' => '10,1',
    ],

    'self_service' => [
        // Middleware del gruppo self-service (/iam/me/delegations). Il guard è dell'app host.
        'middleware' => ['web', 'auth'],
    ],
];
