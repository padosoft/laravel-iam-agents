<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('iam_delegation_grants', function (Blueprint $table): void {
            // Budget consentito (v1.1): {"amount":25.0,"currency":"EUR","tokens":…,"calls":…}.
            // null = nessun vincolo di intensità. Quando presente entra nel binding del
            // consenso e rende l'exchange FAIL-CLOSED senza un DelegationBudgetGuard bindato.
            $table->json('budget')->nullable()->after('purpose');
        });
    }

    public function down(): void
    {
        Schema::table('iam_delegation_grants', function (Blueprint $table): void {
            $table->dropColumn('budget');
        });
    }
};
