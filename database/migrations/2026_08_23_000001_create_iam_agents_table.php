<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_agents', function (Blueprint $table): void {
            // Id = la parte destra del SubjectRef `agent:{id}` (ulid prefissato agt_).
            $table->string('id', 64)->primary();
            $table->string('name');

            // Tripla identità: operator (provider che gestisce l'agente: "openai", "anthropic",
            // "in-house"…) ≠ istanza agente ≠ utente delegante (nella grant).
            $table->string('operator', 128)->nullable()->index();

            // Owner = àncora di accountability (user o org): il retire dell'owner sospende l'agente.
            $table->string('owner_type', 32)->nullable();
            $table->string('owner_id', 64)->nullable();

            // Applicazione del registry i cui scope da manifest sono il TETTO di max_scopes.
            $table->string('application_key', 128)->nullable()->index();

            // Client OAuth con cui l'agente si autentica (private_key_jwt) al token endpoint.
            $table->string('client_id', 128)->nullable()->unique();

            // Tetto degli scope delegabili: sottoinsieme degli scope del manifest, riducibile
            // dall'admin, MAI superabile da una grant.
            $table->json('max_scopes');

            // Lifecycle: pending (registrazione agentic in attesa di approvazione UMANA) →
            // active → suspended/retired. Solo `active` scambia token (fail-closed).
            $table->string('status', 16)->default('pending')->index();

            $table->string('organization_id', 64)->nullable()->index();

            $table->timestamp('approved_at')->nullable();
            $table->string('approved_by', 64)->nullable();
            $table->timestamp('suspended_at')->nullable();
            $table->timestamp('retired_at')->nullable();
            $table->timestamps();

            $table->index(['owner_type', 'owner_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_agents');
    }
};
