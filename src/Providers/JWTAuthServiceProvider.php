<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace ManyHong\JWTAuth\Providers;

use ManyHong\JWTAuth\JWTAuth;
use ManyHong\JWTAuth\Blacklist;
use ManyHong\JWTAuth\JWTManager;
use ManyHong\JWTAuth\Claims\Factory;
use ManyHong\JWTAuth\PayloadFactory;
use Illuminate\Support\ServiceProvider;
use ManyHong\JWTAuth\Commands\JWTGenerateCommand;
use ManyHong\JWTAuth\Validators\PayloadValidator;

class JWTAuthServiceProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Boot the service provider.
     */
    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/config.php' => config_path('jwt.php'),
        ], 'config');

        $this->bootBindings();

        $this->commands('manyhong.jwt.generate');
    }

    /**
     * Bind some Interfaces and implementations.
     */
    protected function bootBindings()
    {
        $this->app['ManyHong\JWTAuth\JWTAuth'] = function ($app) {
            return $app['manyhong.jwt.auth'];
        };

        $this->app['ManyHong\JWTAuth\Providers\User\UserInterface'] = function ($app) {
            return $app['manyhong.jwt.provider.user'];
        };

        $this->app['ManyHong\JWTAuth\Providers\JWT\JWTInterface'] = function ($app) {
            return $app['manyhong.jwt.provider.jwt'];
        };

        $this->app['ManyHong\JWTAuth\Providers\Auth\AuthInterface'] = function ($app) {
            return $app['mnayhong.jwt.provider.auth'];
        };

        $this->app['ManyHong\JWTAuth\Providers\Storage\StorageInterface'] = function ($app) {
            return $app['manyhong.jwt.provider.storage'];
        };

        $this->app['ManyHong\JWTAuth\JWTManager'] = function ($app) {
            return $app['manyhong.jwt.manager'];
        };

        $this->app['ManyHong\JWTAuth\Blacklist'] = function ($app) {
            return $app['manyhong.jwt.blacklist'];
        };

        $this->app['ManyHong\JWTAuth\PayloadFactory'] = function ($app) {
            return $app['manyhong.jwt.payload.factory'];
        };

        $this->app['ManyHong\JWTAuth\Claims\Factory'] = function ($app) {
            return $app['manyhong.jwt.claim.factory'];
        };

        $this->app['ManyHong\JWTAuth\Validators\PayloadValidator'] = function ($app) {
            return $app['manyhong.jwt.validators.payload'];
        };
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        // register providers
        $this->registerUserProvider();
        $this->registerJWTProvider();
        $this->registerAuthProvider();
        $this->registerStorageProvider();
        $this->registerJWTBlacklist();

        $this->registerClaimFactory();
        $this->registerJWTManager();

        $this->registerJWTAuth();
        $this->registerPayloadValidator();
        $this->registerPayloadFactory();
        $this->registerJWTCommand();

        $this->mergeConfigFrom(__DIR__.'/../config/config.php', 'jwt');
    }

    /**
     * Register the bindings for the User provider.
     */
    protected function registerUserProvider()
    {
        $this->app->singleton('manyhong.jwt.provider.user', function ($app) {
            $provider = $this->config('providers.user');
            $model = $app->make(config('auth.providers.'.$this->config('guard').'.model'));
            return new $provider($model);
        });
    }

    /**
     * Register the bindings for the JSON Web Token provider.
     */
    protected function registerJWTProvider()
    {
        $this->app->singleton('manyhong.jwt.provider.jwt', function ($app) {
            $secret = $this->config('secret');
            $algo = $this->config('algo');
            $provider = $this->config('providers.jwt');

            return new $provider($secret, $algo);
        });
    }

    /**
     * Register the bindings for the Auth provider.
     */
    protected function registerAuthProvider()
    {
        $this->app->singleton('manyhong.jwt.provider.auth', function ($app) {
            return $this->getConfigInstance($this->config('providers.auth'));
        });
    }

    /**
     * Register the bindings for the Storage provider.
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('manyhong.jwt.provider.storage', function ($app) {
            return $this->getConfigInstance($this->config('providers.storage'));
        });
    }

    /**
     * Register the bindings for the Payload Factory.
     */
    protected function registerClaimFactory()
    {
        $this->app->singleton('manyhong.jwt.claim.factory', function () {
            return new Factory();
        });
    }

    /**
     * Register the bindings for the JWT Manager.
     */
    protected function registerJWTManager()
    {
        $this->app->singleton('manyhong.jwt.manager', function ($app) {
            $instance = new JWTManager(
                $app['manyhong.jwt.provider.jwt'],
                $app['manyhong.jwt.blacklist'],
                $app['manyhong.jwt.payload.factory']
            );

            return $instance->setBlacklistEnabled((bool) $this->config('blacklist_enabled'));
        });
    }

    /**
     * Register the bindings for the main JWTAuth class.
     */
    protected function registerJWTAuth()
    {
        $this->app->singleton('manyhong.jwt.auth', function ($app) {
            $auth = new JWTAuth(
                $app['manyhong.jwt.manager'],
                $app['manyhong.jwt.provider.user'],
                $app['manyhong.jwt.provider.auth'],
                $app['request']
            );

            return $auth->setIdentifier($this->config('identifier'));
        });
    }

    /**
     * Register the bindings for the main JWTAuth class.
     */
    protected function registerJWTBlacklist()
    {
        $this->app->singleton('manyhong.jwt.blacklist', function ($app) {
            $instance = new Blacklist($app['manyhong.jwt.provider.storage']);
            return $instance->setRefreshTTL($this->config('refresh_ttl'));
        });
    }

    /**
     * Register the bindings for the payload validator.
     */
    protected function registerPayloadValidator()
    {
        $this->app->singleton('manyhong.jwt.validators.payload', function () {
            return with(new PayloadValidator())->setRefreshTTL($this->config('refresh_ttl'))->setRequiredClaims($this->config('required_claims'));
        });
    }

    /**
     * Register the bindings for the Payload Factory.
     */
    protected function registerPayloadFactory()
    {
        $this->app->singleton('manyhong.jwt.payload.factory', function ($app) {
            $factory = new PayloadFactory($app['manyhong.jwt.claim.factory'], $app['request'], $app['manyhong.jwt.validators.payload']);

            return $factory->setTTL($this->config('ttl'));
        });
    }

    /**
     * Register the Artisan command.
     */
    protected function registerJWTCommand()
    {
        $this->app->singleton('manyhong.jwt.generate', function () {
            return new JWTGenerateCommand();
        });
    }

    /**
     * Helper to get the config values.
     *
     * @param  string $key
     * @return string
     */
    protected function config($key, $default = null)
    {
        return config("jwt.$key", $default);
    }

    /**
     * Get an instantiable configuration instance. Pinched from dingo/api :).
     *
     * @param  mixed  $instance
     * @return object
     */
    protected function getConfigInstance($instance)
    {
        if (is_callable($instance)) {
            return call_user_func($instance, $this->app);
        } elseif (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }
}
