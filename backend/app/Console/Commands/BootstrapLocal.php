<?php

namespace App\Console\Commands;

use App\Models\User;
use Illuminate\Console\Command;

class BootstrapLocal extends Command
{
    protected $signature = 'app:bootstrap';

    protected $description = 'Initialize dictionaries and optionally import the existing Flask database once.';

    public function handle(): int
    {
        $this->call('db:seed', ['--class' => 'DictionarySeeder', '--force' => true]);
        $source = config('legacy.source');
        if ($source && is_file($source)) {
            if ($this->call('legacy:import', ['source' => $source]) !== self::SUCCESS) {
                return self::FAILURE;
            }
        }
        if (app()->environment('local') && config('legacy.admin_password') && ! User::where('login', 'admin')->exists()) {
            User::create(['name' => 'Администратор', 'login' => 'admin', 'email' => 'admin@rewatch.local',
                'password' => config('legacy.admin_password'), 'role' => 'admin', 'theme' => 'dark']);
            $this->info('Local administrator is ready. Credentials are in backend/.env.');
        }

        return self::SUCCESS;
    }
}
