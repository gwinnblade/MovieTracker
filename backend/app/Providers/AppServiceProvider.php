<?php

namespace App\Providers;

use App\Auth\LegacyUserProvider;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void {}

    public function boot(): void
    {
        Auth::provider('legacy-eloquent', function ($app, array $config) {
            return new LegacyUserProvider($app['hash'], $config['model']);
        });
        ResetPassword::createUrlUsing(fn ($user, string $token) => rtrim(config('app.frontend_url'), '/').'/reset-password/'.$token.'?email='.rawurlencode($user->email));
        if (config('database.default') === 'sqlite') {
            $dbPath = config('database.connections.sqlite.database');

            if ($dbPath && file_exists($dbPath)) {
                DB::statement('PRAGMA foreign_keys = ON;');
                DB::statement('PRAGMA journal_mode = WAL;');
                DB::statement('PRAGMA synchronous = NORMAL;');
                DB::statement('PRAGMA busy_timeout = 5000;');
            }
        }
    }
}
