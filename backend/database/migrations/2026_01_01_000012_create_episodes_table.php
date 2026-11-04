<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('episodes', function (Blueprint $table) {
            $table->id();
            $table->foreignId('media_id')->index()->constrained('media')->cascadeOnDelete();
            $table->unsignedSmallInteger('season');
            $table->unsignedSmallInteger('number');
            $table->string('title')->nullable();
            $table->timestamps();
            $table->unique(['media_id', 'season', 'number']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('episodes');
    }
};