<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_delegation_grants', function (Blueprint $table): void {
            // Id `dgr_{ulid}`: viaggia nel token come claim privato pds_dgr (revoca mirata).
            $table->string('id', 64)->primary();

            // Il delegante (SubjectRef scomposto: tipicamente user:…).
            $table->string('user_type', 32);
            $table->string('user_id', 64);

            $table->string('agent_id', 64)->index();

            // Scope consentiti (⊆ max_scopes dell'agente alla creazione, ri-validati all'exchange).
            $table->json('scopes');

            // Scopo human-readable, mostrato al consenso e citato nell'audit. Obbligatorio.
            $table->string('purpose');

            // active | suspended | expired | revoked — solo active autorizza (fail-closed).
            $table->string('status', 16)->default('active')->index();

            $table->timestamp('expires_at')->index();

            // Evidenza del consenso step-up: id conferma (UNIQUE = consumazione one-shot:
            // la stessa conferma non può creare due grant) + AAL raggiunto.
            // NB naming: `*_confirmation_id`, MAI chiavi con substring `token` (redaction admin).
            $table->string('consent_confirmation_id', 128)->nullable()->unique();
            $table->string('consent_aal', 8)->nullable();

            $table->timestamp('revoked_at')->nullable();
            $table->string('revoked_by_type', 32)->nullable();
            $table->string('revoked_by_id', 64)->nullable();

            $table->timestamps();

            // Lookup dell'exchange: la grant attiva user→agent.
            $table->index(['user_type', 'user_id', 'agent_id', 'status']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_delegation_grants');
    }
};
