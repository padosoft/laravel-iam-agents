<?php

declare(strict_types=1);

namespace Padosoft\Iam\Agents;

use DateInterval;
use Illuminate\Support\Facades\Route;
use League\OAuth2\Server\AuthorizationServer;
use Padosoft\Iam\Agents\Consent\ConsentVerifier;
use Padosoft\Iam\Agents\Consent\NullConsentVerifier;
use Padosoft\Iam\Agents\Grants\DbDelegationGrantStore;
use Padosoft\Iam\Agents\OAuth\TokenExchangeGrant;
use Padosoft\Iam\Agents\Pdp\DelegatedEngine;
use Padosoft\Iam\Agents\Registry\DbAgentRegistry;
use Padosoft\Iam\Agents\Support\DelegationSessionResolver;
use Padosoft\Iam\Agents\Support\NullDelegationSessionResolver;
use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Contracts\Delegation\AgentRegistry;
use Padosoft\Iam\Contracts\Delegation\DelegatedAuthorizationEngine;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStore;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Domain\OAuth\Token\TokenIssuanceContext;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

/**
 * Service provider del modulo agents (delega RFC 8693). Si registra NEL server IAM
 * (precedente: iam-directory): il grant token-exchange entra nel token endpoint via
 * `extend(AuthorizationServer)`, il PDP delegato è un decorator NUOVO
 * (DelegatedAuthorizationEngine) che lascia intatto l'engine single-subject.
 */
final class IamAgentsServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-iam-agents')
            ->hasConfigFile('iam-agents')
            ->hasMigrations([
                'create_iam_agents_table',
                'create_iam_delegation_grants_table',
            ]);
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(DbAgentRegistry::class);
        $this->app->bind(AgentRegistry::class, DbAgentRegistry::class);
        $this->app->bind(DelegationGrantStore::class, DbDelegationGrantStore::class);

        // Consenso: FQCN da config, default fail-closed (nessuna grant creabile).
        $this->app->bind(ConsentVerifier::class, function (): ConsentVerifier {
            $fqcn = config('iam-agents.consent.verifier');
            if (is_string($fqcn) && $fqcn !== '' && is_a($fqcn, ConsentVerifier::class, true)) {
                $verifier = $this->app->make($fqcn);
                assert($verifier instanceof ConsentVerifier);

                return $verifier;
            }

            return new NullConsentVerifier;
        });

        $this->app->bind(DelegationSessionResolver::class, function (): DelegationSessionResolver {
            $fqcn = config('iam-agents.consent.session_resolver');
            if (is_string($fqcn) && $fqcn !== '' && is_a($fqcn, DelegationSessionResolver::class, true)) {
                $resolver = $this->app->make($fqcn);
                assert($resolver instanceof DelegationSessionResolver);

                return $resolver;
            }

            return new NullDelegationSessionResolver;
        });

        // PDP delegato: interfaccia NUOVA, decorator sull'engine nativo. L'engine
        // single-subject resta intatto per tutti i consumer esistenti.
        $this->app->bind(DelegatedAuthorizationEngine::class, fn (): DelegatedEngine => new DelegatedEngine(
            $this->app->make(AuthorizationEngine::class),
            $this->app->make(AgentRegistry::class),
            $this->app->make(DelegationGrantStore::class),
        ));

        // Il grant RFC 8693 entra nel token endpoint del server SENZA toccare il core:
        // AuthorizationServer è un singleton → extend + enableGrantType. TTL con hard cap.
        if ($this->enabled()) {
            $this->app->extend(AuthorizationServer::class, function (AuthorizationServer $server): AuthorizationServer {
                $grant = new TokenExchangeGrant(
                    $this->app->make(TokenSigner::class),
                    $this->app->make(SessionRegistry::class),
                    $this->app->make(DbAgentRegistry::class),
                    $this->app->make(DelegationGrantStore::class),
                    $this->app->make(TokenIssuanceContext::class),
                    $this->app->make(Audit\DelegationAudit::class),
                    $this->typ(),
                );
                $server->enableGrantType($grant, new DateInterval('PT'.$this->delegatedTtl().'S'));

                return $server;
            });
        }
    }

    public function packageBooted(): void
    {
        // P4: il modulo si dichiara al pannello via GET /capabilities (contratto del server:
        // config `iam.capabilities.*` scritta a boot). Sempre, anche se disabilitato — il
        // pannello distingue "installato ma spento" (false) da "assente" (chiave mancante).
        config()->set('iam.capabilities.modules.agents', $this->enabled());
        config()->set('iam.capabilities.features.agents', [
            'registration' => config('iam-agents.registration.enabled', false) === true,
            'max_delegation_depth' => is_numeric($depth = config('iam-agents.max_delegation_depth', 1)) ? (int) $depth : 1,
        ]);

        // Migrazioni del modulo (pattern del server: loadMigrationsFrom, disattivabile).
        if ((bool) config('iam-agents.run_migrations', true)) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }

        if (!$this->enabled()) {
            return;
        }

        // Self-service ("le mie deleghe") — guard dell'app host.
        $middleware = config('iam-agents.self_service.middleware', ['web', 'auth']);
        Route::prefix('iam/me/delegations')
            ->middleware(is_array($middleware) ? $middleware : ['web', 'auth'])
            ->group(__DIR__.'/../routes/self-service.php');

        // Admin API: STESSO stack del server (alias middleware globali iam.admin_auth /
        // iam.can / iam.idempotency), stesso prefix. Permission slug: iam:agents.manage,
        // iam:delegations.manage (da concedere via catalogo PDP — default-deny finché assenti).
        $prefix = config('iam.admin.route_prefix', 'api/iam/v1');
        Route::prefix(is_string($prefix) ? $prefix : 'api/iam/v1')
            ->middleware(['iam.admin_auth', 'iam.idempotency', 'throttle:120,1'])
            ->group(__DIR__.'/../routes/admin.php');

        // Registrazione agentic (DCR gated + discovery auth.md). OFF di default;
        // le registrazioni atterrano SEMPRE in `pending` (approvazione umana).
        Route::group([], __DIR__.'/../routes/registration.php');
    }

    private function enabled(): bool
    {
        return config('iam-agents.enabled', true) === true;
    }

    private function delegatedTtl(): int
    {
        $ttl = config('iam-agents.tokens.delegated_ttl', 300);
        $ttl = is_numeric($ttl) ? (int) $ttl : 300;

        // Hard cap: oltre, la revoca diventa silenziosamente "fino a scadenza".
        return min(max(1, $ttl), TokenExchangeGrant::MAX_DELEGATED_TTL);
    }

    private function typ(): string
    {
        $typ = config('iam-agents.tokens.typ', 'delegated+jwt');

        return is_string($typ) && $typ !== '' ? $typ : 'delegated+jwt';
    }
}
