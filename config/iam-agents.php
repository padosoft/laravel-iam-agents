<?php

declare(strict_types=1);

// Config del modulo agents (delega RFC 8693). Ogni default è fail-closed: il modulo
// installato ma non configurato non concede nulla.
return [

    // Interruttore del modulo. Anche il server (config('iam.agents.enabled')) può gatearlo:
    // pattern config-flag + 409 come per iam-directory.
    'enabled' => env('IAM_AGENTS_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Correlazione con il run AI (laravel/ai 0.11+)
    |--------------------------------------------------------------------------
    |
    | Stampa `invocation_id` (e l'hop padre, quando un agente è usato come tool)
    | sul contesto di delega ambientale, così ogni log e audit record emesso
    | durante il run si unisce ai record di finops e di eval per la stessa
    | chiave. No-op senza laravel/ai o senza un contesto di delega idratato.
    |
    */

    'run_correlation' => env('IAM_AGENTS_RUN_CORRELATION', true),

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
        // - \Padosoft\Iam\Agents\Consent\RebelStepUpConsentVerifier::class (dynamic linking
        //   PSD2-grade reale; richiede `padosoft/laravel-rebel-step-up` ^0.2 e il purpose
        //   configurato in `rebel-step-up.purposes` con `sca.dynamic_linking` attivo).
        'verifier' => null,

        // FQCN del DelegationSessionResolver: dice al modulo DOVE vive il sid IAM
        // dell'utente corrente (sessione Laravel, cookie, claim — lo sa l'app host).
        // null → NullDelegationSessionResolver (fail-closed: consenso nativo rifiuta).
        'session_resolver' => null,
    ],

    'elevation' => [
        // JIT scope elevation (v1.1): finestra di validità di una richiesta pending.
        // Scaduta ⇒ expired da sola (fail-closed: l'ignorata non eleva mai).
        'pending_ttl_minutes' => env('IAM_AGENTS_ELEVATION_PENDING_TTL', 15),

        // Purpose del RI-consenso step-up dell'elevazione (kebab-case obbligatorio).
        'purpose' => 'iam-delegation-elevation',

        // FQCN dell'ElevationNotifier (canale out-of-band verso il delegante).
        // null → nessuna notifica push: le richieste restano visibili in self-service.
        // Implementazione di riferimento:
        // \Padosoft\Rebel\Channels\Delegation\ChannelElevationNotifier::class (laravel-rebel-channels).
        'notifier' => null,
    ],

    'kill_switch' => [
        // Quante approvazioni di admin DISTINTI servono per far ripartire la delega
        // dopo un freeze. Congelare ne richiede sempre UNA sola: in un incidente
        // l'esitazione costa più di un falso positivo, mentre ripartire è
        // esattamente il momento in cui serve che più di una persona sia d'accordo.
        //
        // Il valore viene FOTOGRAFATO sul freeze nel momento in cui viene creato e
        // non riletto qui allo sblocco: altrimenti chi può modificare questo file
        // lo porterebbe a 1 e scongelerebbe da solo.
        //
        // 1 è ammesso (team piccoli) e significa "nessun quorum": resta comunque
        // l'asimmetria di PERMESSO — `iam:delegations.manage` per congelare,
        // `iam:delegations.unfreeze` per approvare la rimozione.
        'lift_quorum' => env('IAM_AGENTS_FREEZE_LIFT_QUORUM', 2),
    ],

    'receipts' => [
        // Le ricevute d'azione delegata: JWS firmati dall'issuer con cui un agente
        // attesta ciò che ha fatto, e che l'utente vede nella propria timeline.
        // ON di default: coniarle richiede comunque un token delegato valido e una
        // grant viva, quindi la superficie non esiste finché non esiste una delega.
        'enabled' => env('IAM_AGENTS_RECEIPTS_ENABLED', true),

        // Throttle dell'endpoint di emissione ("tentativi,minuti"). Firmare è
        // economico: un agente in loop non deve poter riempire la tabella
        // dell'evidenza.
        'rate_limit' => env('IAM_AGENTS_RECEIPTS_RATE_LIMIT', '120,1'),

        // `exp` del JWS. Una ricevuta non scade — l'evidenza non scade — ma il
        // contratto TokenSigner impone un exp, quindi è messo molto lontano
        // (10 anni) e resta una formalità. Ciò che limita davvero la verifica
        // esterna è la rotazione delle chiavi: per orizzonti di anni, archivia il
        // JWKS storico (il digest sigillato in catena resta probante comunque).
        'ttl_seconds' => env('IAM_AGENTS_RECEIPTS_TTL', 315360000),
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
