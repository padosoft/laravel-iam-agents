<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents\Tests;

use Illuminate\Foundation\Application;
use Padosoft\Rebel\Core\RebelCoreServiceProvider;
use Padosoft\Rebel\EmailOtp\RebelEmailOtpServiceProvider;
use Padosoft\Rebel\StepUp\RebelStepUpServiceProvider;

/**
 * TestCase per l'adapter RebelStepUpConsentVerifier: boota la suite rebel ACCANTO al
 * server IAM + modulo (come in un'app host che installa entrambi). rebel-step-up è
 * require-dev: in produzione l'adapter si attiva solo se il pacchetto c'è.
 */
abstract class RebelTestCase extends TestCase
{
    /**
     * @param  Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return array_merge(parent::getPackageProviders($app), [
            RebelCoreServiceProvider::class,
            RebelEmailOtpServiceProvider::class,
            RebelStepUpServiceProvider::class,
        ]);
    }

    /** @param  Application  $app */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        // Pepper del keyed-hash rebel (binding digest, ecc.) — obbligatorio.
        $app['config']->set('rebel-core.peppers', [1 => 'test-pepper']);
        $app['config']->set('rebel-core.pepper_current', 1);
        $app['config']->set('rebel-email-otp.timing_target_ms', 0);
    }

    protected function defineDatabaseMigrations(): void
    {
        // I provider rebel PUBBLICANO le migrazioni ma non le caricano: nei test
        // vanno caricate dai vendor path (stesso pattern del TestCase di rebel-step-up).
        $this->loadMigrationsFrom(__DIR__.'/../vendor/padosoft/laravel-rebel-core/database/migrations');
        $this->loadMigrationsFrom(__DIR__.'/../vendor/padosoft/laravel-rebel-email-otp/database/migrations');
        $this->loadMigrationsFrom(__DIR__.'/../vendor/padosoft/laravel-rebel-step-up/database/migrations');
    }
}
