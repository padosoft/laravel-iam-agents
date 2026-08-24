<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_delegation_elevations', function (Blueprint $table): void {
            // Id `elv_{ulid}`.
            $table->string('id', 64)->primary();
            $table->string('grant_id', 64)->index();

            // Scope AGGIUNTIVI richiesti (mai già coperti dalla grant al momento della richiesta).
            $table->json('requested_scopes');

            // Perché l'agente chiede l'elevazione: mostrato al delegante. Obbligatorio.
            $table->string('reason');

            // pending | approved | denied | expired — pending scade da solo (fail-closed).
            $table->string('status', 16)->default('pending')->index();
            $table->timestamp('expires_at')->index();

            // Evidenza del RI-consenso step-up (stessa semantica one-shot delle grant).
            $table->string('consent_confirmation_id', 128)->nullable()->unique();
            $table->string('consent_aal', 8)->nullable();

            $table->timestamp('decided_at')->nullable();

            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_delegation_elevations');
    }
};
