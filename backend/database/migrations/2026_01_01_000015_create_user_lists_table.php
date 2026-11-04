<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('user_lists', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->index()->constrained('users')->cascadeOnDelete();
            $table->string('name');
            $table->boolean('is_public')->default(false);
            $table->string('share_token', 64)->nullable()->unique(); // ссылка для доступа
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('user_lists');
    }
};