<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Governance;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStore;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;
use Padosoft\Iam\Domain\Governance\Reviews\Reviewable\ReviewableRef;
use Padosoft\Iam\Domain\Governance\Reviews\Reviewable\ReviewableSource;

/**
 * Le delegation grant come accessi certificabili nelle access review dell'IAM (IGA).
 *
 * Una grant attiva è il permesso, dato da un umano, perché un agente agisca per suo conto: è un
 * accesso esattamente come un grant RBAC, e come tale va ri-guardato periodicamente. Il ciclo di
 * vita delle deleghe è per costruzione più corto di quello dei ruoli, ma è anche più facile da
 * dimenticare — nessuno "lascia l'azienda" al posto di un agente.
 *
 * Segnali pensati per questo dominio, non copiati da quello dei grant: quando è stata usata
 * davvero (dalle ricevute firmate), quanto manca alla scadenza, se l'agente nel frattempo è stato
 * sospeso, con che AAL è stato dato il consenso.
 */
final class DelegationGrantReviewableSource implements ReviewableSource
{
    public const TYPE = 'delegation_grant';

    /** Soglia di dormienza in giorni, se la config non dice altro. */
    private const DEFAULT_UNUSED_DAYS = 30;

    public function __construct(private readonly DelegationGrantStore $grants) {}

    public function type(): string
    {
        return self::TYPE;
    }

    public function label(): string
    {
        return 'Delegation grants';
    }

    public function scoped(ReviewCampaign $campaign): iterable
    {
        $grants = $this->query($campaign)->get();
        if ($grants->isEmpty()) {
            return;
        }

        $ids = [];
        $agentIds = [];
        foreach ($grants as $grant) {
            $ids[] = $grant->id;
            $agentIds[$grant->agent_id] = true;
        }

        $lastUsed = $this->lastUsedAt($ids);
        $agents = $this->agents(array_keys($agentIds));
        $reviewer = $this->resolveReviewer($campaign);
        $unusedDays = $this->unusedDaysThreshold();

        foreach ($grants as $grant) {
            $agent = $agents[$grant->agent_id] ?? null;
            $usedAt = $lastUsed[$grant->id] ?? null;
            $neverUsed = $usedAt === null;
            $lastUsedDays = $usedAt !== null ? (int) $usedAt->diffInDays(now()) : null;

            yield new ReviewableRef(
                type: self::TYPE,
                id: $grant->id,
                // Il delegante è il reviewer naturale: è lui che ha dato il consenso, ed è lui che
                // sa se l'agente serve ancora. La strategia `named` della campagna, se valorizzata,
                // ha comunque la precedenza (un audit centralizzato deve poter scavalcare).
                reviewer: $reviewer ?? $grant->user_type.':'.$grant->user_id,
                signals: [
                    'never_used' => $neverUsed,
                    'dormant' => $neverUsed || ($lastUsedDays !== null && $lastUsedDays >= $unusedDays),
                    'last_used_days' => $lastUsedDays,
                    'expires_in_days' => (int) now()->diffInDays($grant->expires_at, false),
                    'agent_status' => $agent?->status,
                    // Un agente sospeso con deleghe ancora attive è il caso da chiudere per primo:
                    // la delega tornerebbe viva insieme all'agente, senza che nessuno riconfermi.
                    'agent_suspended' => $agent !== null && $agent->status !== 'active',
                    'scopes_count' => count($grant->scopes),
                    'consent_aal' => $grant->consent_aal,
                    'has_budget' => is_array($grant->budget) && $grant->budget !== [],
                ],
            );
        }
    }

    public function revoke(string $id, string $by, string $reason, array $context = []): bool
    {
        $grant = DelegationGrantModel::query()->find($id);
        if ($grant === null || $grant->status === DelegationGrantStatus::Revoked->value) {
            return false; // idempotente: già revocata o sparita
        }

        // Passa dallo store, non dal model: è lui che audita (stream=delegation) ed emette
        // DelegationGrantRevoked, su cui sono agganciati i consumer (rebel-ai-guard, finops…).
        $this->grants->revoke($id, $this->reviewerRef($by));

        return true;
    }

    public function describeMany(array $ids): array
    {
        if ($ids === []) {
            return [];
        }

        $grants = DelegationGrantModel::query()->whereIn('id', $ids)->get();
        $agentIds = [];
        foreach ($grants as $grant) {
            $agentIds[$grant->agent_id] = true;
        }
        $agents = $this->agents(array_keys($agentIds));

        $out = [];
        foreach ($grants as $grant) {
            $agent = $agents[$grant->agent_id] ?? null;
            $out[$grant->id] = [
                // Stessi nomi di campo dei grant RBAC dove il concetto coincide, così il console
                // rende una riga sola per entrambi i tipi senza sapere quale sta guardando.
                'subject_type' => $grant->user_type,
                'subject_id' => $grant->user_id,
                'privilege_type' => 'delegation',
                'privilege_key' => implode(' ', $grant->scopes),
                'application_key' => $agent?->application_key,
                'effect' => 'permit',
                // Campi propri della delega: chi agisce, perché, fino a quando.
                'agent_id' => $grant->agent_id,
                'agent_name' => $agent?->name,
                'purpose' => $grant->purpose,
                'expires_at' => $grant->expires_at->toIso8601String(),
                'grant_status' => $grant->status,
            ];
        }

        return $out;
    }

    /**
     * Le grant ATTIVE nello scope. Filtri additivi; `agent_ids` restringe a specifici agenti.
     *
     * @return Builder<DelegationGrantModel>
     */
    private function query(ReviewCampaign $campaign): Builder
    {
        $scope = $campaign->scope_json ?? [];
        $query = DelegationGrantModel::query()
            ->where('status', DelegationGrantStatus::Active->value)
            ->where('expires_at', '>', now());

        // Isolamento cross-tenant: la grant non porta l'org, la porta l'agente. Una campagna di
        // tenant certifica solo le deleghe verso agenti di quel tenant; gli agenti globali
        // (organization_id null) restano alla campagna globale, come per i grant.
        if ($campaign->organization_id !== null) {
            $query->whereIn(
                'agent_id',
                Agent::query()->where('organization_id', $campaign->organization_id)->select('id')
            );
        }

        $agentIds = self::stringList($scope['agent_ids'] ?? null);
        if ($agentIds !== []) {
            $query->whereIn('agent_id', $agentIds);
        }

        return $query;
    }

    /**
     * Ultimo uso reale per grant, dalle ricevute firmate. UNA aggregazione per l'intera campagna:
     * il "dormant" di N deleghe non deve costare N query.
     *
     * @param  list<string>  $ids
     * @return array<string, Carbon>
     */
    private function lastUsedAt(array $ids): array
    {
        $rows = DB::table('iam_delegation_receipts')
            ->selectRaw('grant_id, max(issued_at) as last_used_at')
            ->whereIn('grant_id', $ids)
            ->groupBy('grant_id')
            ->get();

        $out = [];
        foreach ($rows as $row) {
            $grantId = $row->grant_id ?? null;
            $at = $row->last_used_at ?? null;
            if (is_string($grantId) && is_string($at) && $at !== '') {
                $out[$grantId] = Carbon::parse($at);
            }
        }

        return $out;
    }

    /**
     * @param  array<array-key, mixed>  $ids
     * @return array<string, Agent>
     */
    private function agents(array $ids): array
    {
        if ($ids === []) {
            return [];
        }

        $out = [];
        foreach (Agent::query()->whereIn('id', array_values($ids))->get() as $agent) {
            $out[$agent->id] = $agent;
        }

        return $out;
    }

    private function resolveReviewer(ReviewCampaign $campaign): ?string
    {
        if ($campaign->reviewer_strategy === 'named') {
            $named = $campaign->scope_json['reviewer'] ?? null;

            return is_string($named) && $named !== '' ? $named : null;
        }

        return null;
    }

    /** `type:id` → SubjectRef; una stringa senza `:` diventa un soggetto di sistema. */
    private function reviewerRef(string $by): SubjectRef
    {
        $parts = explode(':', $by, 2);
        if (count($parts) === 2 && $parts[0] !== '' && $parts[1] !== '') {
            return new SubjectRef($parts[0], $parts[1]);
        }

        return new SubjectRef('system', $by);
    }

    private function unusedDaysThreshold(): int
    {
        $value = config('iam-agents.reviews.unused_days', self::DEFAULT_UNUSED_DAYS);

        return is_int($value) && $value > 0 ? $value : self::DEFAULT_UNUSED_DAYS;
    }

    /**
     * @return list<string>
     */
    private static function stringList(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $out = [];
        foreach ($value as $v) {
            if (is_string($v) && $v !== '') {
                $out[] = $v;
            }
        }

        return $out;
    }
}
