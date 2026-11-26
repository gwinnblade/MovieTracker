<?php

namespace App\Console\Commands;

use App\Models\User;
use Illuminate\Console\Command;

class MakeModerator extends Command
{
    protected $signature = 'user:moderator {login} {--admin : Assign administrator role}';

    protected $description = 'Grant moderation rights to an existing local account.';

    public function handle(): int
    {
        $user = User::where('login', $this->argument('login'))->first();
        if (! $user) {
            $this->error('Account not found.');

            return self::FAILURE;
        }
        $user->role = $this->option('admin') ? 'admin' : 'moderator';
        $user->save();
        $this->info('Moderation rights updated.');

        return self::SUCCESS;
    }
}
