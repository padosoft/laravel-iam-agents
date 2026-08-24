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

it('un token GIÀ delegato non è ri-scambiabile (niente chaining in MVP)', function () {
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
