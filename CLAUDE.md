# CLAUDE.md — laravel-iam-agents

Guida per agenti AI che lavorano in questo repo (package dell'ecosistema **Laravel IAM**).
Convenzioni di processo comuni: vedi `RULES.md` di `laravel-iam-contracts`/`laravel-iam-server`.

## Cos'è questo package

**Delegated access for AI agents**: il modulo opzionale del server IAM che rende gli agenti AI
identità di prima classe con delega esplicita, revocabile e auditabile.

- **Composer:** `padosoft/laravel-iam-agents`
- **Namespace:** `Padosoft\Iam\Agents\`
- **Dipende da:** `laravel-iam-contracts` (namespace `Delegation\`), `laravel-iam-server`
  (token endpoint, TokenSigner, SessionRegistry, audit hash-chain, `TokenIssuanceContext`),
  `league/oauth2-server` (il grant custom).

## L'invariante (NON violare, MAI)

**Un token delegato porta DUE identità (`sub` = utente, `act` = agente) e ogni decisione è
l'INTERSEZIONE STRETTA di ciò che può fare l'utente e ciò che può fare l'agente. Mai l'unione.
Fail-closed ovunque.**

Corollari non negoziabili:
1. **L'agente non riceve MAI il token dell'utente come credenziale.** Lo scambia (RFC 8693).
2. **TTL delegato ≤ 900s hard cap** (`TokenExchangeGrant::MAX_DELEGATED_TTL`), **niente refresh
   token**: il ri-exchange È il check di freshness della revoca. Alzare il cap = convertire la
   revoca in "fino a scadenza".
3. **Solo `active` delega**: agente pending/suspended/retired ⇒ deny; grant non-Active ⇒ deny;
   sessione utente morta ⇒ deny; subject token senza `sid` ⇒ deny (la delega richiede un umano).
4. **Mai auto-provisioning**: le registrazioni agentic (DCR/auth.md) atterrano in `pending`;
   `active` SOLO con approvazione umana. Un agente autentica SOLO via `private_key_jwt`.
5. **Consenso = evidenza**: challenge step-up vincolata all'hash canonico di
   (agent, scopes, ttl, purpose — e `budget`, quando presente: v1.1);
   `consent_confirmation_id` è UNIQUE (one-shot). La revoca è sempre più facile del consenso
   (mai step-up per revocare).
6. **Ogni exchange (emesso O rifiutato) e ogni mutazione è auditata** su `stream=delegation`
   (hash-chain del server). Nei metadata di audit MAI chiavi con substring `token`
   (`grant_id`, `*_confirmation_id` — le admin API redigono per substring).
7. **Il claim `act` malformato LANCIA, mai degrada** a token utente pieno
   (`DelegationChain::fromTokenClaims`). I token delegati sono **introspection-mandatory**
   per le resource server: il `typ: delegated+jwt` è igiene, non l'unica difesa.
8. **`DelegatedAuthorizationEngine` è un'interfaccia NUOVA** ("add, don't mutate"): il
   decorator `DelegatedEngine` non altera mai il check single-subject dell'engine interno.
9. **Budget fail-closed (v1.1)**: una grant CON budget e nessun `DelegationBudgetGuard` bindato
   ⇒ exchange RIFIUTATO (`delegation_budget_unenforceable`) — mai "budget ignorato". Il modulo
   non misura: definisce la porta (il meter di riferimento è laravel-ai-finops).
10. **JIT elevation (v1.1)**: solo su grant Active, solo scope EXTRA, MAI oltre `max_scopes`
   (il ceiling admin non si alza col consenso); `pending` scade da solo; approvare = RI-consenso
   step-up bound agli scope extra (one-shot); negare è one-click; il notifier out-of-band
   (rebel-channels) INFORMA soltanto, best-effort, mai autoritativo.
11. **Kill switch ASIMMETRICO (v1.3)**: congelare = UN admin (`iam:delegations.manage`), immediato,
   senza approvazioni; scongelare = quorum di admin **DISTINTI** (unique `(freeze_id, approver)` a
   livello di schema) con un permesso a sé (`iam:delegations.unfreeze`). Il `required_quorum` è
   **fotografato sulla riga del freeze** alla creazione e MAI riletto dalla config allo sblocco —
   altrimenti chi può modificare la config lo abbassa a 1 e scongela da solo. Chi ha congelato può
   approvare come chiunque altro (escluderlo non aggiunge sicurezza e toglie una firma a chi gestisce
   l'incidente). Il freeze blocca exchange, decisioni delegate ed elevation; **non blocca MAI la
   revoca né la sospensione di un agente** (un kill switch che impedisce la risposta all'incidente è
   peggio di nessun kill switch). Il check NON è cachato: un kill switch che impiega 30s a uccidere
   non è un kill switch. Stato illeggibile ⇒ deny `freeze_state_unavailable`; tabella non ancora
   migrata ⇒ non blocca nulla (è "non installato", non "non verificabile").

## Architettura

- `OAuth/TokenExchangeGrant` — il grant RFC 8693, registrato nel token endpoint del server via
  `app()->extend(AuthorizationServer::class)` (nessuna modifica al core). Deposita
  `act`/`pds_dgr`/`aud`/`typ` nel `TokenIssuanceContext` del server (P1).
- `Pdp/DelegatedEngine` — intersection PDP (decorator, due passi `check()` + grant attiva).
- `Consent/` — `ConsentVerifier` (porta) + `IamNativeConsentVerifier` (step-up nativo, binding
  emulato module-side) + `NullConsentVerifier` (default fail-closed). Adapter rebel-step-up
  dopo il patch upstream P5 (`BindingSource`).
- `Http/Controllers/` — self-service `/iam/me/delegations`, Admin API (stack middleware del
  server: `iam.admin_auth` + `iam.can:iam:agents.manage|iam:delegations.manage`), registrazione
  DCR gated, discovery `agent-auth.json` + `AUTH.md`.
- `Audit/DelegationAudit` — emettitore dello stream `delegation`.

## Gate (come server/contracts)

```bash
vendor/bin/pint --test && vendor/bin/phpstan analyse --memory-limit=1G && vendor/bin/pest
```

I test E2E (`tests/Feature/TokenExchangeTest.php`) SONO il criterio di accettazione del loop:
exchange felice + OGNI rifiuto (test negativi obbligatori). Non rimuoverli mai; ogni nuova
feature aggiunge PRIMA il suo test negativo.

## Setup dev locale (finché i branch upstream non sono mergiati)

Il modulo richiede `laravel-iam-contracts` col namespace `Delegation\` e `laravel-iam-server`
con `TokenIssuanceContext` (branch `task/delegation-contracts` e `task/delegation-core-p1-p3`).
In locale: path-repositories verso i checkout dei due repo con `options.versions` a `1.99.0`
(NON committare quelle entry). Nota tooling: `phpstan/phpstan` è dist-only e l'ambiente può
bloccare api.github.com — vedi LESSON.md di `laravel-iam-server`.
