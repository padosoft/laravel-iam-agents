<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Tests;

use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as Orchestra;
use Padosoft\Iam\Agents\IamAgentsServiceProvider;
use Padosoft\Iam\Domain\Audit\Webhooks\WebhookUrlGuard;
use Padosoft\Iam\IamServiceProvider;

abstract class TestCase extends Orchestra
{
    /**
     * Il modulo boota SOPRA il server IAM (come in produzione): il grant token-exchange
     * entra nel token endpoint del server via extend(AuthorizationServer).
     *
     * @param  Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            IamServiceProvider::class,
            IamAgentsServiceProvider::class,
        ];
    }

    /** @param  Application  $app */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('a', 32)));
        $app['config']->set('cache.default', 'array');

        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
            'foreign_key_constraints' => true,
        ]);

        // KEK di test (32 byte) per il layer crypto del server (firma ES256 dei token).
        $app['config']->set('iam.crypto.kek', base64_encode(str_repeat('K', 32)));

        // Grant core attivi nei test end-to-end (l'exchange richiede subject token reali).
        $app['config']->set('iam.oauth.grants', [
            'client_credentials' => true,
            'authorization_code' => true,
            'refresh_token' => true,
        ]);

        // Come nel TestCase del server: l'URL-guard dei webhook risolve l'hostname (difesa
        // DNS-rebinding) e i test usano host non risolvibili (pep.test) — resolver
        // deterministico su IP pubblico così il guard non li blocca.
        $app->bind(
            WebhookUrlGuard::class,
            fn (): WebhookUrlGuard => new WebhookUrlGuard(fn (string $host): array => ['93.184.216.34']),
        );
    }
}
