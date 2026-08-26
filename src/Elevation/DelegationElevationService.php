<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Elevation;

use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Agents\Audit\DelegationAudit;
use Padosoft\Iam\Agents\Consent\ConsentFailedException;
use Padosoft\Iam\Agents\Consent\ConsentPayload;
use Padosoft\Iam\Agents\Consent\ConsentVerifier;
use Padosoft\Iam\Agents\Freeze\DelegationFreezeService;
use Padosoft\Iam\Agents\Freeze\DelegationFrozenException;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationElevationModel;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Contracts\Delegation\ActorRef;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStatus;
use Padosoft\Iam\Contracts\Delegation\ElevationNotifier;
use Padosoft\Iam\Contracts\Delegation\ElevationRequest;
use Padosoft\Iam\Contracts\Identity\SessionRef;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * JIT scope elevation (v1.1): un'azione FUORI dalla grant non muore in un flat
 * deny — l'agente (via orchestratore, server-side) chiede al delegante di
 * estendere il consenso agli scope mancanti.
 *
 * Regole fail-closed, non negoziabili:
 *  - la richiesta nasce SOLO su una grant Active e per scope ⊆ max_scopes
 *    dell'agente e NON già coperti dalla grant;
 *  - `pending` scade da solo (config `elevation.pending_ttl_minutes`);
 *  - l'approvazione è un RI-consenso step-up con dynamic linking sugli scope
 *    aggiuntivi (stesso ConsentVerifier del consenso, purpose dedicato) e la
 *    conferma è one-shot (UNIQUE su consent_confirmation_id);
 *  - il notifier out-of-band (rebel-channels) INFORMA soltanto ed è best-effort:
 *    la consegna fallita è auditata, la richiesta resta comunque visibile e
 *    approvabile in self-service;
 *  - negare non richiede MAI step-up (negare dev'essere più facile che concedere).
 */
final class DelegationElevationService
{
    public function __construct(
        private readonly ConsentVerifier $consent,
        private readonly DelegationAudit $audit,
        private readonly ?DelegationFreezeService $freeze = null,
    ) {}

    /**
     * Apre la richiesta di elevazione e (best-effort) la notifica out-of-band.
     *
     * @param  list<string>  $scopes  scope AGGIUNTIVI richiesti
     */
    public function request(string $grantId, array $scopes, string $reason): ElevationRequest
    {
        $grant = DelegationGrantModel::query()->find($grantId);
        if ($grant === null || $grant->status !== DelegationGrantStatus::Active->value || now() >= $grant->expires_at) {
            throw new ElevationException('Elevation su grant assente o non attiva.');
        }

        $agent = Agent::query()->find($grant->agent_id);
        if ($agent === null) {
            throw new ElevationException('Elevation su agente ignoto.');
        }

        // Kill switch: una flotta congelata non allarga i propri scope. Sarebbe
        // il contrario esatto di ciò che il freeze significa — e, peggio, la
        // richiesta arriverebbe al delegante come una notifica out-of-band
        // durante un incidente, chiedendogli di concedere DI PIÙ.
        if ($this->freeze !== null) {
            try {
                $this->freeze->assertNotFrozen($agent->id, $agent->organization_id);
            } catch (DelegationFrozenException $e) {
                throw new ElevationException('Elevation rifiutata: la delega è congelata ('.$e->reason.').');
            }
        }

        $clean = array_values(array_unique(array_filter($scopes, static fn (string $s): bool => $s !== '')));
        sort($clean);
        if ($clean === [] || $reason === '') {
            throw new ElevationException('Elevation senza scope o senza reason.');
        }

        $current = array_filter($grant->scopes, 'is_string');
        $extra = array_values(array_diff($clean, $current));
        if ($extra === []) {
            throw new ElevationException('Gli scope richiesti sono già coperti dalla grant.');
        }

        // Il ceiling dell'agente resta invalicabile ANCHE via elevation: il manifest
        // approvato dagli admin è il limite strutturale, il consenso non lo alza.
        $ceiling = array_filter($agent->max_scopes, 'is_string');
        $outside = array_diff($extra, $ceiling);
        if ($outside !== []) {
            throw new ElevationException('Scope fuori dal ceiling dell\'agente: '.implode(', ', $outside).'.');
        }

        $row = DelegationElevationModel::query()->create([
            'id' => DelegationElevationModel::newId(),
            'grant_id' => $grant->id,
            'requested_scopes' => $extra,
            'reason' => $reason,
            'status' => DelegationElevationModel::STATUS_PENDING,
            'expires_at' => now()->addMinutes($this->pendingTtlMinutes()),
        ]);

        $request = new ElevationRequest(
            id: $row->id,
            grantId: $grant->id,
            user: new SubjectRef($grant->user_type, $grant->user_id),
            agent: new SubjectRef(ActorRef::SUBJECT_TYPE, $agent->id),
            agentName: $agent->name,
            requestedScopes: $extra,
            reason: $reason,
            expiresAt: $row->expires_at->toDateTimeImmutable(),
        );

        $this->audit->elevationRequested($row, $agent->name);

        // Notifica out-of-band BEST-EFFORT: il fallimento di consegna non annulla la
        // richiesta (resta in self-service), ma va auditato — mai inghiottito muto.
        // Il gate è la CONFIG (il binding container esiste sempre): notifier assente
        // = scelta esplicita dell'host, nessun rumore in audit.
        $notifierFqcn = config('iam-agents.elevation.notifier');
        if (is_string($notifierFqcn) && $notifierFqcn !== '') {
            try {
                app(ElevationNotifier::class)->notify($request);
                $this->audit->elevationNotified($row, true);
            } catch (\Throwable $e) {
                $this->audit->elevationNotified($row, false, $e->getMessage());
            }
        }

        return $request;
    }

    /**
     * Passo 1 dell'approvazione: apre la challenge step-up VINCOLATA agli scope
     * aggiuntivi (dynamic linking). I parametri del binding sono derivati
     * server-side dalla riga (immutabile) — l'utente approva ESATTAMENTE ciò
     * che l'agente ha chiesto, mai una variante.
     *
     * @return array{challenge_id: string, method: string, expires_at: string}
     */
    public function approveChallenge(string $elevationId, SubjectRef $user, ?SessionRef $session): array
    {
        [$row, $grant] = $this->pendingRowFor($elevationId, $user);

        return $this->consent->challenge($user, $this->consentPayloadFor($row, $grant), $session);
    }

    /**
     * Passo 2: verifica la challenge e, one-shot, estende la grant.
     *
     * @param  array<string, mixed>  $verification  es. ['code' => '123456']
     */
    public function approve(string $elevationId, SubjectRef $user, string $challengeId, array $verification): void
    {
        [$row, $grant] = $this->pendingRowFor($elevationId, $user);

        try {
            $evidence = $this->consent->verifyAndConsume($user, $this->consentPayloadFor($row, $grant), $challengeId, $verification);
        } catch (ConsentFailedException $e) {
            throw new ElevationException('Ri-consenso fallito: '.$e->getMessage());
        }

        DB::transaction(function () use ($row, $grant, $evidence): void {
            $extra = array_values(array_filter($row->requested_scopes, 'is_string'));
            $merged = array_values(array_unique(array_merge(array_filter($grant->scopes, 'is_string'), $extra)));
            sort($merged);

            $grant->fill(['scopes' => $merged])->save();

            $row->fill([
                'status' => DelegationElevationModel::STATUS_APPROVED,
                'consent_confirmation_id' => $evidence->confirmationId, // UNIQUE ⇒ one-shot
                'consent_aal' => $evidence->aal->value,
                'decided_at' => now(),
            ])->save();

            $this->audit->elevationDecided($row, 'approved');
        });
    }

    /** Negare è one-click: MAI step-up per rifiutare un'estensione di autorità. */
    public function deny(string $elevationId, SubjectRef $user): void
    {
        [$row] = $this->pendingRowFor($elevationId, $user);

        $row->fill(['status' => DelegationElevationModel::STATUS_DENIED, 'decided_at' => now()])->save();
        $this->audit->elevationDecided($row, 'denied');
    }

    /**
     * Le richieste pending (non scadute) del delegante, per il self-service.
     *
     * @return list<array<string, mixed>>
     */
    public function pendingFor(SubjectRef $user): array
    {
        $out = [];
        $rows = DelegationElevationModel::query()
            ->where('status', DelegationElevationModel::STATUS_PENDING)
            ->where('expires_at', '>', now())
            ->orderByDesc('created_at')
            ->get();

        foreach ($rows as $row) {
            $grant = DelegationGrantModel::query()->find($row->grant_id);
            if ($grant === null || $grant->user_type !== $user->type || $grant->user_id !== $user->id) {
                continue;
            }
            $out[] = [
                'id' => $row->id,
                'grant_id' => $row->grant_id,
                'agent_name' => is_string($name = Agent::query()->whereKey($grant->agent_id)->value('name')) ? $name : '',
                'requested_scopes' => array_values(array_filter($row->requested_scopes, 'is_string')),
                'reason' => $row->reason,
                'expires_at' => $row->expires_at->toDateTimeImmutable()->format(\DateTimeInterface::ATOM),
            ];
        }

        return $out;
    }

    /**
     * La riga pending DELL'UTENTE (ownership verificata) o eccezione. Le righe
     * scadute vengono marcate `expired` al primo tocco (lazy, fail-closed).
     *
     * @return array{DelegationElevationModel, DelegationGrantModel}
     */
    private function pendingRowFor(string $elevationId, SubjectRef $user): array
    {
        $row = DelegationElevationModel::query()->find($elevationId);
        if ($row === null) {
            throw new ElevationException('Richiesta di elevazione inesistente.');
        }

        $grant = DelegationGrantModel::query()->find($row->grant_id);
        if ($grant === null || $grant->user_type !== $user->type || $grant->user_id !== $user->id) {
            throw new ElevationException('Richiesta di elevazione inesistente.'); // niente esistenza ad altrui
        }

        if ($row->status === DelegationElevationModel::STATUS_PENDING && now() >= $row->expires_at) {
            $row->fill(['status' => DelegationElevationModel::STATUS_EXPIRED])->save();
        }
        if (!$row->isPendingAt(now())) {
            throw new ElevationException('Richiesta di elevazione non più decidibile (scaduta o già decisa).');
        }
        if ($grant->status !== DelegationGrantStatus::Active->value) {
            throw new ElevationException('La grant sottostante non è più attiva.');
        }

        return [$row, $grant];
    }

    /**
     * Il payload del RI-consenso: gli scope AGGIUNTIVI, il ttl residuo della grant,
     * il purpose dedicato all'elevazione. Derivato server-side dalla riga — è il
     * dynamic linking dell'elevazione.
     */
    private function consentPayloadFor(DelegationElevationModel $row, DelegationGrantModel $grant): ConsentPayload
    {
        $remaining = max(1, (int) now()->diffInSeconds($grant->expires_at, false));

        return new ConsentPayload(
            agentId: $grant->agent_id,
            scopes: array_values(array_filter($row->requested_scopes, 'is_string')),
            ttlSeconds: $remaining,
            purpose: $this->purpose().': '.$row->reason,
        );
    }

    private function purpose(): string
    {
        $purpose = config('iam-agents.elevation.purpose', 'iam-delegation-elevation');

        return is_string($purpose) && $purpose !== '' ? $purpose : 'iam-delegation-elevation';
    }

    private function pendingTtlMinutes(): int
    {
        $minutes = config('iam-agents.elevation.pending_ttl_minutes', 15);

        return is_numeric($minutes) && (int) $minutes > 0 ? (int) $minutes : 15;
    }
}
