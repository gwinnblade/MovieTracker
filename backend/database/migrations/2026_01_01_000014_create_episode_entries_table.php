<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('episode_entries', function (Blueprint $table) {
            $table->id();
            $table->foreignId('entry_id')->index()->constrained('entries')->cascadeOnDelete();
            $table->foreignId('episode_id')->index()->constrained('episodes')->cascadeOnDelete();
            $table->boolean('watched')->default(false);
            $table->unsignedTinyInteger('rating')->nullable();
            $table->text('note')->nullable();
            $table->timestamps();
            $table->unique(['entry_id', 'episode_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('episode_entries');
    }
};