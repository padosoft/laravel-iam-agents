<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;

uses(RefreshDatabase::class);

const REG_PAYLOAD = [
    'client_name' => 'Shopping Copilot',
    'operator' => 'openai',
    'token_endpoint_auth_method' => 'private_key_jwt',
    'jwks' => ['keys' => [['kty' => 'EC', 'crv' => 'P-256', 'kid' => 'k1', 'x' => 'x', 'y' => 'y']]],
];

it('registrazione spenta (default) ⇒ 404: mai auto-provisioning implicito', function () {
    config()->set('iam-agents.registration.enabled', false);

    $this->postJson('/oauth/register', REG_PAYLOAD)->assertStatus(404);
    expect(Agent::query()->count())->toBe(0);
});

it('registrazione attiva ⇒ la candidatura atterra in PENDING con zero grant e zero scope', function () {
    config()->set('iam-agents.registration.enabled', true);

    $response = $this->postJson('/oauth/register', REG_PAYLOAD)->assertStatus(201);

    expect($response->json('status'))->toBe('pending_approval')
        ->and($response->json('grant_types'))->toBe([])
        ->and($response->json())->not->toHaveKey('client_secret');   // mai un secret

    $agent = Agent::query()->firstOrFail();
    expect($agent->statusEnum())->toBe(AgentStatus::Pending)
        ->and($agent->max_scopes)->toBe([])                          // least privilege: scope solo all'approvazione
        ->and($agent->client_id)->toBeNull();                        // nessun client finché un umano non approva
});

it('senza private_key_jwt la candidatura è rifiutata (nessun shared secret per gli agenti)', function () {
    config()->set('iam-agents.registration.enabled', true);

    $payload = REG_PAYLOAD;
    $payload['token_endpoint_auth_method'] = 'client_secret_basic';

    $this->postJson('/oauth/register', $payload)->assertStatus(400)
        ->assertJsonPath('error', 'invalid_client_metadata');
});

it('la discovery agent-auth.json espone il contratto di delega', function () {
    $json = $this->getJson('/.well-known/agent-auth.json')->assertOk()->json('agent_auth');

    expect($json['grant_types_supported'])->toBe(['urn:ietf:params:oauth:grant-type:token-exchange'])
        ->and($json['token_endpoint_auth_methods_supported'])->toBe(['private_key_jwt'])
        ->and($json['delegation']['act_claim'])->toBeTrue()
        ->and($json['delegation']['max_delegation_depth'])->toBe(1)
        ->and($json['registration_endpoint'])->toBeNull(); // spenta di default
});

it('AUTH.md è servito come markdown e spiega exchange e intersezione', function () {
    $response = $this->get('/AUTH.md')->assertOk();

    expect($response->headers->get('Content-Type'))->toContain('text/markdown')
        ->and($response->getContent())->toContain('urn:ietf:params:oauth:grant-type:token-exchange')
        ->and($response->getContent())->toContain('strict intersection');
});
