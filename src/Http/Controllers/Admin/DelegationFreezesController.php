<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Http\Controllers\Admin;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Agents\Freeze\DelegationFreezeService;
use Padosoft\Iam\Agents\Freeze\FreezeException;
use Padosoft\Iam\Agents\Freeze\FreezeScope;
use Padosoft\Iam\Agents\Models\DelegationFreezeApprovalModel;
use Padosoft\Iam\Agents\Models\DelegationFreezeModel;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use ValueError;

/**
 * Admin API del kill switch.
 *
 * L'asimmetria è visibile già nel routing: `POST delegation-freezes` è gated su
 * `iam:delegations.manage` — chiunque amministri la delega può fermarla — mentre
 * `POST .../approve-lift` è gated su `iam:delegations.unfreeze`, un permesso a sé
 * che si concede a meno persone. Il quorum è il secondo asse; questo è il primo.
 */
final class DelegationFreezesController
{
    public function __construct(private readonly DelegationFreezeService $freezes) {}

    public function index(Request $request): JsonResponse
    {
        $query = DelegationFreezeModel::query()->orderByDesc('frozen_at');

        // Default: solo gli ATTIVI. Chi apre questa pagina durante un incidente
        // vuole sapere cosa è fermo adesso, non la storia.
        if (!$request->boolean('include_lifted')) {
            $query->whereNull('lifted_at');
        }

        $freezes = $query->limit(100)->get();

        $approvals = DelegationFreezeApprovalModel::query()
            ->whereIn('freeze_id', $freezes->pluck('id'))
            ->orderBy('approved_at')
            ->get()
            ->groupBy('freeze_id');

        return new JsonResponse([
            'data' => $freezes->map(fn (DelegationFreezeModel $freeze): array => $this->present($freeze, array_values($approvals->get($freeze->id)?->all() ?? [])))->all(),
        ]);
    }

    public function show(string $id): JsonResponse
    {
        $freeze = DelegationFreezeModel::query()->find($id);

        if ($freeze === null) {
            return new JsonResponse(['error' => 'not_found'], 404);
        }

        $approvals = array_values(
            DelegationFreezeApprovalModel::query()
                ->where('freeze_id', $freeze->id)
                ->orderBy('approved_at')
                ->get()
                ->all(),
        );

        return new JsonResponse(['data' => $this->present($freeze, $approvals)]);
    }

    public function store(Request $request): JsonResponse
    {
        try {
            $scope = FreezeScope::from($request->string('scope', FreezeScope::Global->value)->toString());
        } catch (ValueError) {
            return new JsonResponse(['error' => 'invalid_scope', 'allowed' => array_column(FreezeScope::cases(), 'value')], 422);
        }

        try {
            $freeze = $this->freezes->freeze(
                $scope,
                $request->string('scope_id')->toString() ?: null,
                $request->string('reason')->toString(),
                $this->actor($request, 'frozen_by'),
            );
        } catch (FreezeException $e) {
            return new JsonResponse(['error' => 'invalid_freeze', 'message' => $e->getMessage()], 422);
        }

        return new JsonResponse(['data' => $this->present($freeze, [])], 201);
    }

    public function approveLift(Request $request, string $id): JsonResponse
    {
        try {
            $outcome = $this->freezes->approveLift($id, $this->actor($request, 'approver'), $request->string('note')->toString() ?: null);
        } catch (FreezeException $e) {
            return new JsonResponse(['error' => 'invalid_lift', 'message' => $e->getMessage()], 422);
        }

        return new JsonResponse(['data' => $outcome->toArray()]);
    }

    /**
     * Chi sta agendo. Il subject arriva dal contesto admin del server quando c'è;
     * il parametro esplicito è il fallback per gli stack che non lo espongono.
     * Un'approvazione senza identità sarebbe un quorum senza quorum, quindi il
     * default è deliberatamente inutilizzabile due volte: `admin` è UNA identità,
     * e l'unique `(freeze_id, approver)` impedisce che valga per due firme.
     */
    private function actor(Request $request, string $parameter): SubjectRef
    {
        $explicit = $request->string($parameter)->toString();

        if ($explicit !== '') {
            return new SubjectRef('user', $explicit);
        }

        $context = $request->attributes->get('iam_admin_subject');

        return $context instanceof SubjectRef ? $context : new SubjectRef('user', 'admin');
    }

    /**
     * @param  list<DelegationFreezeApprovalModel>  $approvals
     * @return array<string, mixed>
     */
    private function present(DelegationFreezeModel $freeze, array $approvals): array
    {
        return [
            'id' => $freeze->id,
            'scope' => $freeze->scope,
            'scope_id' => $freeze->scope_id,
            'reason' => $freeze->reason,
            'frozen_by' => $freeze->frozen_by,
            'frozen_at' => $freeze->frozen_at->toDateTimeImmutable()->format(\DateTimeInterface::ATOM),
            'active' => $freeze->isActive(),
            'required_quorum' => $freeze->required_quorum,
            'approvals' => array_map(static fn (DelegationFreezeApprovalModel $a): array => [
                'approver' => $a->approver,
                'note' => $a->note,
                'approved_at' => $a->approved_at->toDateTimeImmutable()->format(\DateTimeInterface::ATOM),
            ], $approvals),
            'remaining_approvals' => $freeze->isActive() ? $freeze->remainingApprovals(count($approvals)) : 0,
            'lifted_at' => $freeze->lifted_at?->toDateTimeImmutable()->format(\DateTimeInterface::ATOM),
            'lifted_by' => $freeze->lifted_by,
        ];
    }
}
