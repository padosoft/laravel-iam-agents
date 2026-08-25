<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Context;
use Laravel\Ai\Contracts\Agent;
use Laravel\Ai\Contracts\Providers\TextProvider;
use Laravel\Ai\Events\AgentFailed;
use Laravel\Ai\Events\AgentPrompted;
use Laravel\Ai\Events\StartingStep;
use Laravel\Ai\Gateway\ParentInvocation;
use Laravel\Ai\Prompts\AgentPrompt;
use Laravel\Ai\Responses\AgentResponse;
use Laravel\Ai\Responses\Data\Meta;
use Laravel\Ai\Responses\Data\Usage;
use Padosoft\Iam\Agents\Support\RunCorrelation;

function startingStep(string $invocationId): StartingStep
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

function agentPrompt(): AgentPrompt
{
    return new AgentPrompt(
        Mockery::mock(Agent::class),
        'hi',
        [],
        Mockery::mock(TextProvider::class),
        'gpt-4o-mini',
    );
}

function agentResponse(string $invocationId): AgentResponse
{
    return new AgentResponse($invocationId, 'answer', new Usage, new Meta(provider: 'openai', model: 'gpt-4o-mini'));
}

it('stamps the invocation id onto an existing delegation context', function (): void {
    Context::add(RunCorrelation::CONTEXT_KEY, ['sub' => 'user:42', 'grant_id' => 'dgr_1']);

    app(RunCorrelation::class)->handleStartingStep(startingStep('inv_1'));

    $context = Context::get(RunCorrelation::CONTEXT_KEY);

    expect($context['invocation_id'])->toBe('inv_1')
        ->and($context['sub'])->toBe('user:42')
        ->and($context['grant_id'])->toBe('dgr_1');
});

it('does not invent a delegation context for a run that has none', function (): void {
    app(RunCorrelation::class)->handleStartingStep(startingStep('inv_2'));

    expect(Context::get(RunCorrelation::CONTEXT_KEY))->toBeNull();
});

it('records the parent hop when an agent runs as a tool of another', function (): void {
    Context::add(RunCorrelation::CONTEXT_KEY, ['sub' => 'user:42']);

    ParentInvocation::within('inv_parent', 'tool_call_7', function (): void {
        app(RunCorrelation::class)->handleStartingStep(startingStep('inv_child'));
    });

    $context = Context::get(RunCorrelation::CONTEXT_KEY);

    expect($context['invocation_id'])->toBe('inv_child')
        ->and($context['parent_invocation_id'])->toBe('inv_parent')
        ->and($context['parent_tool_invocation_id'])->toBe('tool_call_7');
});

it('clears the invocation id when the run finishes, so later logs are not attributed to it', function (): void {
    Context::add(RunCorrelation::CONTEXT_KEY, ['sub' => 'user:42']);

    $correlation = app(RunCorrelation::class);
    $correlation->handleStartingStep(startingStep('inv_3'));
    $correlation->handleRunFinished(new AgentPrompted('inv_3', agentPrompt(), agentResponse('inv_3')));

    $context = Context::get(RunCorrelation::CONTEXT_KEY);

    expect($context)->not->toHaveKey('invocation_id')
        ->and($context['sub'])->toBe('user:42');
});

it('clears it on a terminal failure too', function (): void {
    Context::add(RunCorrelation::CONTEXT_KEY, ['sub' => 'user:42']);

    $correlation = app(RunCorrelation::class);
    $correlation->handleStartingStep(startingStep('inv_4'));
    $correlation->handleRunFinished(new AgentFailed('inv_4', agentPrompt(), new RuntimeException('gave up')));

    expect(Context::get(RunCorrelation::CONTEXT_KEY))->not->toHaveKey('invocation_id');
});

it('leaves another run alone when a different invocation finishes', function (): void {
    Context::add(RunCorrelation::CONTEXT_KEY, ['sub' => 'user:42']);

    $correlation = app(RunCorrelation::class);
    $correlation->handleStartingStep(startingStep('inv_5'));
    // A sibling run finishing must not strip the id of the one still going.
    $correlation->handleRunFinished(new AgentPrompted('inv_other', agentPrompt(), agentResponse('inv_other')));

    expect(Context::get(RunCorrelation::CONTEXT_KEY)['invocation_id'])->toBe('inv_5');
});
