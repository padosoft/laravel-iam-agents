<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_delegation_receipts', function (Blueprint $table): void {
            // Id `rcp_{ulid}`.
            $table->string('id', 64)->primary();

            $table->string('grant_id', 64)->index();
            $table->string('agent_id', 64)->index();

            // Il delegante. Indicizzato perché la query che conta è "cosa hanno
            // fatto i MIEI agenti".
            $table->string('subject_type', 32);
            $table->string('subject_id', 128);

            $table->string('action');
            $table->string('resource')->nullable();

            // ok | failed | denied — l'esito che l'attore dichiara.
            $table->string('outcome', 16);

            // La decisione del PDP che ha permesso l'azione, quando il PEP la
            // conosce: è ciò che lega l'asserzione dell'attore a un fatto
            // verificabile lato server.
            $table->string('decision_id', 64)->nullable();

            $table->timestamp('issued_at');

            // Il JWS compatto: la metà PORTABILE della ricevuta, che l'utente
            // esporta e chiunque verifica col JWKS.
            $table->text('jws');

            // Digest del payload canonico: la metà DUREVOLE, sigillata in catena
            // d'audit, che resta probante anche dopo la rotazione della chiave.
            $table->string('payload_digest', 80)->index();

            // Le reti mobili ritentano: due POST identici non devono produrre due
            // ricevute della stessa azione.
            $table->string('idempotency_key', 128)->nullable();

            $table->timestamps();

            $table->index(['subject_type', 'subject_id', 'issued_at'], 'iam_delegation_receipts_subject_idx');
            $table->unique(['grant_id', 'idempotency_key']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_delegation_receipts');
    }
};
