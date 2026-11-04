<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\DB;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
    }

    public function boot(): void
    {
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