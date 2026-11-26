<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('genre_media', function (Blueprint $table) {
            $table->foreignId('media_id')->index()->constrained('media')->cascadeOnDelete();
            $table->foreignId('genre_id')->index()->constrained('genres')->cascadeOnDelete();
            $table->primary(['media_id', 'genre_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('genre_media');
    }
};