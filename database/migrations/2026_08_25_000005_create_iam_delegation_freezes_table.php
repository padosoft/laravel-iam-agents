<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_delegation_freezes', function (Blueprint $table): void {
            // Id `frz_{ulid}`.
            $table->string('id', 64)->primary();

            // global | organization | agent. `scope_id` è l'org o l'agente per gli
            // ultimi due, null per il primo.
            $table->string('scope', 16);
            $table->string('scope_id', 64)->nullable();

            // Perché il freeze esiste. OBBLIGATORIO: un kill switch senza motivo è
            // un kill switch che nessuno sa quando togliere.
            $table->string('reason');

            $table->string('frozen_by', 128);
            $table->timestamp('frozen_at');

            // Il quorum è FOTOGRAFATO qui, non riletto dalla config al momento della
            // rimozione: altrimenti chi può modificare la config abbassa il quorum a 1
            // e scongela da solo — il controllo non proteggerebbe nulla.
            $table->unsignedTinyInteger('required_quorum');

            $table->timestamp('lifted_at')->nullable();
            $table->string('lifted_by', 128)->nullable();

            $table->timestamps();

            // Il lookup della hot path: "esiste un freeze ATTIVO che copre questo?".
            $table->index(['lifted_at', 'scope', 'scope_id'], 'iam_delegation_freezes_active_idx');
        });

        Schema::create('iam_delegation_freeze_approvals', function (Blueprint $table): void {
            $table->id();
            $table->string('freeze_id', 64);
            $table->string('approver', 128);
            $table->string('note')->nullable();
            $table->timestamp('approved_at');

            // Il quorum è di admin DISTINTI: senza questo vincolo una sola identità
            // che approva m volte soddisfa un quorum di m, e l'asimmetria sparisce.
            $table->unique(['freeze_id', 'approver']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_delegation_freeze_approvals');
        Schema::dropIfExists('iam_delegation_freezes');
    }
};
