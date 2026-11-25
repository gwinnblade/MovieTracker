<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('genres', function (Blueprint $table) {
            $table->id();
            $table->string('name_ru')->nullable();
            $table->string('name_en')->nullable();
            $table->timestamps();
            $table->unique(['name_ru', 'name_en']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('genres');
    }
};