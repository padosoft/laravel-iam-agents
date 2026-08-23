<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Http\Controllers\Admin;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Delegation\ActorRef;
use Padosoft\Iam\Contracts\Delegation\DelegatedAuthorizationEngine;
use Padosoft\Iam\Contracts\Delegation\DelegationChain;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Il punto di decisione DELEGATO per i PEP (laravel-iam-client & co.): stessa forma
 * del /decisions/check del server, ma con `actors` (catena) e `delegation_grant_id`.
 * La risposta cita entrambi i soggetti (sub_decisions per layer).
 *
 * Fail-closed: catena assente/malformata ⇒ 422, mai un check single-subject
 * implicito — un token con act NON è mai valutabile come token utente pieno.
 */
final class DelegatedDecisionsController
{
    public function __construct(private readonly DelegatedAuthorizationEngine $engine) {}

    public function check(Request $request): JsonResponse
    {
        $subject = $request->input('subject');
        if (!is_array($subject) || !is_string($subject['type'] ?? null) || !is_string($subject['id'] ?? null)) {
            return new JsonResponse(['error' => 'invalid_subject'], 422);
        }

        $actors = $request->input('actors');
        if (!is_array($actors) || $actors === []) {
            return new JsonResponse(['error' => 'invalid_actors', 'message' => 'actors (catena agent:id) richiesti'], 422);
        }
        $chain = [];
        foreach ($actors as $actor) {
            if (!is_string($actor) || !str_starts_with($actor, ActorRef::SUBJECT_TYPE.':')) {
                return new JsonResponse(['error' => 'invalid_actors', 'message' => 'actor non valido: atteso agent:<id>'], 422);
            }
            $chain[] = ActorRef::fromAgentId(substr($actor, strlen(ActorRef::SUBJECT_TYPE) + 1));
        }

        $query = [];
        foreach (['permission', 'organization', 'application', 'resource', 'context', 'relation', 'object'] as $key) {
            if ($request->has($key)) {
                $query[$key] = $request->input($key);
            }
        }
        $grantId = $request->string('delegation_grant_id')->toString();
        if ($grantId !== '') {
            $query['delegation_grant_id'] = $grantId;
        }

        $decision = $this->engine->checkDelegated(
            new SubjectRef($subject['type'], $subject['id']),
            new DelegationChain(...$chain),
            $query,
        );

        return new JsonResponse($decision);
    }
}
