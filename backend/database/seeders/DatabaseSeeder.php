<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        if (User::count() === 0) {
            if (app()->environment('local')) {
                User::create([
                    'name' => 'Главный Админ',
                    'login' => 'admin',
                    'email' => 'admin@movietracker.local',
                    'password' => Hash::make('SuperAdmin2026!'),
                    'role' => 'admin',
                ]);

                $this->command->info('');
                $this->command->info('АВТОМАТИЧЕСКИ СОЗДАН УЧЕТНАЯ ЗАПИСЬ АДМИНИСТРАТОРА:');
                $this->command->info('Логин: admin');
                $this->command->info('Пароль: SuperAdmin2026!');
                $this->command->info('');
            }
        }

        $this->call([
            DictionarySeeder::class
        ]);
    }
}