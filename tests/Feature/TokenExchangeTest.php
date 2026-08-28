<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Testing\TestResponse;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Contracts\Delegation\ActClaim;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStore;
use Padosoft\Iam\Contracts\Identity\SessionMeta;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Identity\Models\User;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\OAuth\Models\OauthScope;

uses(RefreshDatabase::class);

/**
 * Il loop di accettazione del delegated access, end-to-end sul VERO token endpoint:
 * agente registrato → grant consentita → exchange → token a doppia identità →
 * revoca → l'exchange successivo fallisce. Ogni rifiuto è un test negativo.
 *
 * @return array{agent: Agent, grant: DelegationGrantModel, subjectToken: string, sid: string, userId: string}
 */
function seedExchangeWorld(): array
{
    $user = User::query()->create(['email' => 'delegante@test.it', 'name' => 'Delegante']);
    $userId = (string) $user->id;

    foreach (['orders:read', 'orders:write'] as $scope) {
        OauthScope::query()->create(['identifier' => $scope, 'description' => $scope]);
    }

    $client = OauthClient::query()->create([
        'client_id' => 'cli_agent_test',
        'name' => 'CRM Agent',
        'redirect_uris' => [],
        'grants' => [ActClaim::GRANT_TYPE_TOKEN_EXCHANGE],
        'scopes' => ['orders:read', 'orders:write'],
        'is_confidential' => true,
    ]);
    $client->secret = Hash::make('agent-s3cret');
    $client->save();

    $agent = Agent::query()->create([
        'id' => Agent::newId(),
        'name' => 'CRM Agent',
        'operator' => 'anthropic',
        'client_id' => 'cli_agent_test',
        'max_scopes' => ['orders:read', 'orders:write'],
        'status' => AgentStatus::Active->value,
    ]);

    $session = app(SessionRegistry::class)->start(new SubjectRef('user', $userId), new SessionMeta);
    $subjectToken = app(TokenSigner::class)->issue([
        'sub' => $userId, 'sid' => $session->id, 'aud' => 'cli_webapp', 'scope' => 'openid',
    ], 900);

    $grant = DelegationGrantModel::query()->create([
        'id' => DelegationGrantModel::newId(),
        'user_type' => 'user',
        'user_id' => $userId,
        'agent_id' => $agent->id,
        'scopes' => ['orders:read'],
        'purpose' => 'Assistenza ordini',
        'status' => DelegationGrantStatus::Active->value,
        'expires_at' => now()->addDay(),
        'consent_aal' => 'aal2',
    ]);

    return ['agent' => $agent, 'grant' => $grant, 'subjectToken' => $subjectToken, 'sid' => $session->id, 'userId' => $userId];
}

/**
 * @param  array<string, string|null>  $overrides
 */
function exchangeRequest(string $subjectToken, array $overrides = []): TestResponse
{
    $params = array_merge([
        'grant_type' => ActClaim::GRANT_TYPE_TOKEN_EXCHANGE,
        'client_id' => 'cli_agent_test',
        'client_secret' => 'agent-s3cret',
        'subject_token' => $subjectToken,
        'subject_token_type' => ActClaim::TOKEN_TYPE_ACCESS,
    ], $overrides);

    return test()->post(route('iam.oauth.token'), array_filter($params, static fn ($v): bool => $v !== null));
}

/** @return array<string, mixed> */
function delegatedClaims(string $jwt): array
{
    return app(TokenSigner::class)->parse($jwt);
}

it('scambia il token utente per un token delegato a doppia identità (sub + act + pds_dgr)', function () {
    $world = seedExchangeWorld();

    $response = exchangeRequest($world['subjectToken']);
    $response->assertOk();

    $body = $response->json();
    expect($body['issued_token_type'])->toBe(ActClaim::TOKEN_TYPE_ACCESS)   // RFC 8693 §2.2
        ->and($body['scope'])->toBe('orders:read')                           // sempre esplicito
        ->and($body['expires_in'])->toBeLessThanOrEqual(300);                // TTL corto by design

    $claims = delegatedClaims($body['access_token']);
    expect($claims['sub'])->toBe($world['userId'])                                    // l'utente resta il sub
        ->and($claims['act'])->toBe(['sub' => (string) $world['agent']->subject()])
        ->and($claims['pds_dgr'])->toBe($world['grant']->id)
        ->and($claims['scope'])->toBe('orders:read');

    // Header typ dedicato (igiene di spec per i verifier act-aware).
    $header = json_decode(base64_decode(strtr(explode('.', $body['access_token'])[0], '-_', '+/')), true);
    expect($header['typ'] ?? null)->toBe('delegated+jwt');
});

it('interseca gli scope: richiesti ∩ grant ∩ max_scopes (mai unione)', function () {
    $world = seedExchangeWorld();

    // orders:write è nei max_scopes dell'agente ma NON nella grant ⇒ intersezione vuota.
    exchangeRequest($world['subjectToken'], ['scope' => 'orders:write'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_scope');
});

it('senza grant attiva l\'exchange è negato', function () {
    $world = seedExchangeWorld();
    $world['grant']->delete();

    exchangeRequest($world['subjectToken'])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('grant revocata ⇒ l\'exchange successivo fallisce (il loop di revoca chiude)', function () {
    $world = seedExchangeWorld();

    exchangeRequest($world['subjectToken'])->assertOk();

    app(DelegationGrantStore::class)->revoke($world['grant']->id, new SubjectRef('user', $world['userId']));

    exchangeRequest($world['subjectToken'])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('agente non attivo (pending/suspended/retired) ⇒ deny', function (string $status) {
    $world = seedExchangeWorld();
    $world['agent']->fill(['status' => $status])->save();

    exchangeRequest($world['subjectToken'])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
})->with(['pending', 'suspended', 'retired']);

it('sessione utente revocata ⇒ l\'exchange è negato (freshness della revoca)', function () {
    $world = seedExchangeWorld();

    app(SessionRegistry::class)->revokeSession($world['sid'], 'test-revoca');

    exchangeRequest($world['subjectToken'])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('subject token senza sessione (es. m2m) ⇒ negato: la delega richiede un umano', function () {
    $world = seedExchangeWorld();
    $noSession = app(TokenSigner::class)->issue(['sub' => $world['userId'], 'aud' => 'cli_x'], 900);

    exchangeRequest($noSession)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('con depth=1 (default) un token GIÀ delegato non è ri-scambiabile', function () {
    $world = seedExchangeWorld();

    $delegated = exchangeRequest($world['subjectToken'])->json('access_token');

    exchangeRequest($delegated)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('actor_token è rifiutato con invalid_request pulito (conformance wire, multi-hop v2)', function () {
    $world = seedExchangeWorld();

    exchangeRequest($world['subjectToken'], ['actor_token' => 'x'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
});

it('audience richiesta finisce nell\'aud del token delegato (RFC 8707)', function () {
    $world = seedExchangeWorld();

    $body = exchangeRequest($world['subjectToken'], ['audience' => 'mcp://crm-tools'])->assertOk()->json();

    // lcobucci normalizza `aud` ad array nel parse.
    expect(delegatedClaims($body['access_token'])['aud'])->toBe(['mcp://crm-tools']);
});

it('il token delegato è introspettabile e porta act (verità server-side per le RS)', function () {
    $world = seedExchangeWorld();

    $delegated = exchangeRequest($world['subjectToken'])->json('access_token');

    $intro = test()->post(route('iam.oauth.introspect'), [
        'token' => $delegated,
        'client_id' => 'cli_agent_test',
        'client_secret' => 'agent-s3cret',
    ])->assertOk()->json();

    expect($intro['active'])->toBeTrue()
        ->and($intro['sub'] ?? null)->toBe($world['userId']);
});

/*
|--------------------------------------------------------------------------
| Multi-hop: chaining A→B quando max_delegation_depth lo consente
|--------------------------------------------------------------------------
*/

/** Secondo agente, con client proprio: e' lui che si presenta per l'hop successivo. */
function seedSecondAgent(array $maxScopes = ['orders:read']): Agent
{
    $client = OauthClient::query()->create([
        'client_id' => 'cli_agent_downstream',
        'name' => 'Downstream Agent',
        'redirect_uris' => [],
        'grants' => [ActClaim::GRANT_TYPE_TOKEN_EXCHANGE],
        'scopes' => ['orders:read', 'orders:write'],
        'is_confidential' => true,
    ]);
    $client->secret = Hash::make('downstream-s3cret');
    $client->save();

    return Agent::query()->create([
        'id' => Agent::newId(),
        'name' => 'Downstream Agent',
        'operator' => 'anthropic',
        'client_id' => 'cli_agent_downstream',
        'max_scopes' => $maxScopes,
        'status' => AgentStatus::Active->value,
    ]);
}

/** Abilita il multi-hop: la grant viene costruita quando l'AuthorizationServer si risolve. */
function allowDepth(int $depth): void
{
    config()->set('iam-agents.max_delegation_depth', $depth);
    app()->forgetInstance(League\OAuth2\Server\AuthorizationServer::class);
}

function downstreamExchange(string $subjectToken, array $overrides = []): TestResponse
{
    return exchangeRequest($subjectToken, array_merge([
        'client_id' => 'cli_agent_downstream',
        'client_secret' => 'downstream-s3cret',
    ], $overrides));
}

it('con depth=2 un token delegato e\' ri-scambiabile e l\'act diventa annidato', function () {
    $world = seedExchangeWorld();
    $downstream = seedSecondAgent();
    allowDepth(2);

    $firstHop = exchangeRequest($world['subjectToken'])->assertOk()->json('access_token');
    $secondHop = downstreamExchange($firstHop)->assertOk()->json('access_token');

    $claims = delegatedClaims($secondHop);

    // `sub` resta l'UTENTE: la delega non cambia mai per conto di chi si agisce.
    expect($claims['sub'])->toBe($world['userId'])
        // Attore corrente (piu' esterno) = chi ha appena chiamato; dentro, chi l'ha delegato.
        ->and($claims[ActClaim::ACT]['sub'])->toBe('agent:'.$downstream->id)
        ->and($claims[ActClaim::ACT][ActClaim::ACT]['sub'])->toBe('agent:'.$world['agent']->id)
        // La grant radice resta quella dell'utente verso il PRIMO agente.
        ->and($claims['pds_dgr'])->toBe($world['grant']->id);
});

it('la grant RADICE governa tutta la catena: revocarla uccide anche gli hop a valle', function () {
    $world = seedExchangeWorld();
    seedSecondAgent();
    allowDepth(2);

    $firstHop = exchangeRequest($world['subjectToken'])->assertOk()->json('access_token');
    downstreamExchange($firstHop)->assertOk();

    // L'utente revoca il consenso dato al PRIMO agente: il secondo non ha una grant
    // propria da cui attingere, quindi si ferma anche lui.
    $world['grant']->fill(['status' => DelegationGrantStatus::Revoked->value])->save();

    downstreamExchange($firstHop)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('gli scope si restringono al tetto di OGNI hop, non solo dell\'ultimo', function () {
    $world = seedExchangeWorld();
    // La grant concede orders:read; il downstream ha un tetto che NON lo include.
    seedSecondAgent(['orders:write']);
    allowDepth(2);

    $firstHop = exchangeRequest($world['subjectToken'])->assertOk()->json('access_token');

    // Intersezione vuota: nessuno scope sopravvive a tutti gli anelli.
    downstreamExchange($firstHop)->assertStatus(400)->assertJsonPath('error', 'invalid_scope');
});

it('una catena che rientra su se stessa (A→B→A) e\' rifiutata', function () {
    $world = seedExchangeWorld();
    seedSecondAgent();
    allowDepth(3);

    $firstHop = exchangeRequest($world['subjectToken'])->assertOk()->json('access_token');
    $secondHop = downstreamExchange($firstHop)->assertOk()->json('access_token');

    // A prova a rientrare nella catena che ha originato lui stesso.
    exchangeRequest($secondHop)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('oltre max_delegation_depth la catena si ferma', function () {
    $world = seedExchangeWorld();
    seedSecondAgent();
    allowDepth(2);

    $firstHop = exchangeRequest($world['subjectToken'])->assertOk()->json('access_token');
    $secondHop = downstreamExchange($firstHop)->assertOk()->json('access_token');

    // Il terzo hop supererebbe depth=2. Serve un terzo agente per non incrociare
    // il rifiuto per ciclo, che e' un motivo diverso.
    $third = Agent::query()->create([
        'id' => Agent::newId(), 'name' => 'Third', 'operator' => 'anthropic',
        'client_id' => 'cli_agent_third', 'max_scopes' => ['orders:read'],
        'status' => AgentStatus::Active->value,
    ]);
    $c = OauthClient::query()->create([
        'client_id' => 'cli_agent_third', 'name' => 'Third', 'redirect_uris' => [],
        'grants' => [ActClaim::GRANT_TYPE_TOKEN_EXCHANGE], 'scopes' => ['orders:read'],
        'is_confidential' => true,
    ]);
    $c->secret = Hash::make('third-s3cret');
    $c->save();
    expect($third->id)->not->toBeEmpty();

    exchangeRequest($secondHop, ['client_id' => 'cli_agent_third', 'client_secret' => 'third-s3cret'])
        ->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});
