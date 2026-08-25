<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Context;
use Laravel\Ai\Contracts\Agent;
use Laravel\Ai\Contracts\Providers\TextProvider;
use Laravel\Ai\Events\StartingStep;
use Laravel\Ai\Gateway\ParentInvocation;
use Padosoft\Iam\Agents\Audit\DelegationAudit;
use Padosoft\Iam\Agents\Support\RunCorrelation;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;

uses(RefreshDatabase::class);

/**
 * {@see RunCorrelationTest} copre la stampa dell'id sul contesto. Qui l'altra
 * metà: quel contesto deve finire NELL'AUDIT, non solo nei log dell'app.
 *
 * Senza, la console può solo ordinare gli eventi di delega per timestamp e
 * sperare — e due agenti che scambiano nello stesso secondo diventano
 * indistinguibili proprio quando serve distinguerli.
 */
function correlatedStep(string $invocationId): StartingStep
{
    return new StartingStep(
        $invocationId,
        1,
        Mockery::mock(Agent::class),
        Mockery::mock(TextProvider::class),
        'gpt-4o-mini',
        false,
        [],
        null,
    );
}

it('correla ogni evento di delega al run AI in corso, con l hop padre', function (): void {
    Context::add(RunCorrelation::CONTEXT_KEY, ['sub' => 'user:42']);

    ParentInvocation::within('inv_parent', 'tool_call_7', function (): void {
        app(RunCorrelation::class)->handleStartingStep(correlatedStep('inv_child'));
        app(DelegationAudit::class)->exchange('agt_1', 'user:42', true, ['orders:read'], 'dgr_1');
    });

    $event = AuditEvent::query()->where('event_type', 'iam.delegation.exchange.issued')->firstOrFail();

    expect($event->metadata_json['invocation_id'])->toBe('inv_child')
        ->and($event->metadata_json['parent_invocation_id'])->toBe('inv_parent')
        ->and($event->metadata_json['parent_tool_invocation_id'])->toBe('tool_call_7')
        // Il metadata proprio dell'emettitore resta intatto accanto alla correlazione.
        ->and($event->metadata_json['grant_id'])->toBe('dgr_1');
});

it('non inventa una correlazione quando non c e un run', function (): void {
    app(DelegationAudit::class)->exchange('agt_1', 'user:42', false, [], null, 'no_grant');

    $event = AuditEvent::query()->where('event_type', 'iam.delegation.exchange.refused')->firstOrFail();

    expect($event->metadata_json)->not->toHaveKey('invocation_id')
        ->and($event->metadata_json)->not->toHaveKey('parent_invocation_id')
        ->and($event->metadata_json['refusal_reason'])->toBe('no_grant');
});

it('un run radice non si inventa un padre', function (): void {
    Context::add(RunCorrelation::CONTEXT_KEY, ['sub' => 'user:42']);
    app(RunCorrelation::class)->handleStartingStep(correlatedStep('inv_root'));

    app(DelegationAudit::class)->exchange('agt_1', 'user:42', true, ['orders:read'], 'dgr_1');

    $event = AuditEvent::query()->where('event_type', 'iam.delegation.exchange.issued')->firstOrFail();

    expect($event->metadata_json['invocation_id'])->toBe('inv_root')
        ->and($event->metadata_json)->not->toHaveKey('parent_invocation_id');
});

it('ignora un contesto di delega che non porta un run', function (): void {
    // Il middleware idrata sub/actors/grant_id anche quando nessun SDK gira.
    Context::add(RunCorrelation::CONTEXT_KEY, ['sub' => 'user:42', 'grant_id' => 'dgr_9']);

    app(DelegationAudit::class)->exchange('agt_1', 'user:42', true, ['orders:read'], 'dgr_9');

    $event = AuditEvent::query()->where('event_type', 'iam.delegation.exchange.issued')->firstOrFail();

    expect($event->metadata_json)->not->toHaveKey('invocation_id')
        ->and($event->metadata_json['grant_id'])->toBe('dgr_9');
});
