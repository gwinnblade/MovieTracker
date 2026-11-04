<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('media', function (Blueprint $table) {
            $table->id();
            $table->foreignId('type_id')->index()->constrained('media_types')->restrictOnDelete();
            $table->foreignId('franchise_id')->nullable()->index()->constrained('franchises')->nullOnDelete();
            $table->string('title_ru');
            $table->string('title_en')->nullable();
            $table->string('original_title')->nullable();
            $table->text('description_ru')->nullable();
            $table->string('poster_key')->nullable();
            $table->date('release_date')->nullable();
            $table->string('moderation_status', 20)->default('approved')->index(); 
            $table->timestamps();
            $table->index('title_ru');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('media');
    }
};