<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Http\Controllers\Admin;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStore;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Admin API delle deleghe: ricerca org-wide (per agente, utente, stato) e revoca.
 * La revoca admin è il kill-switch centrale citato da ogni pannello dell'ecosistema.
 */
final class DelegationGrantsController
{
    public function __construct(private readonly DelegationGrantStore $store) {}

    public function index(Request $request): JsonResponse
    {
        $query = DelegationGrantModel::query()->orderByDesc('created_at');

        $agentId = $request->string('agent_id')->toString();
        if ($agentId !== '') {
            $query->where('agent_id', $agentId);
        }
        $userId = $request->string('user_id')->toString();
        if ($userId !== '') {
            $query->where('user_id', $userId);
        }
        $status = $request->string('status')->toString();
        if ($status !== '') {
            $query->where('status', $status);
        }

        return new JsonResponse(['data' => $query->limit(100)->get()]);
    }

    public function revoke(Request $request, string $id): JsonResponse
    {
        $grant = $this->store->find($id);
        if ($grant === null) {
            return new JsonResponse(['error' => 'not_found'], 404);
        }

        $actor = $request->string('revoked_by')->toString();
        $this->store->revoke($id, new SubjectRef('user', $actor !== '' ? $actor : 'admin'));

        return new JsonResponse(status: 204);
    }
}
