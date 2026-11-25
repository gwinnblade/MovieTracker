<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('list_media', function (Blueprint $table) {
            $table->foreignId('user_list_id')->index()->constrained('user_lists')->cascadeOnDelete();
            $table->foreignId('media_id')->index()->constrained('media')->cascadeOnDelete();
            $table->primary(['user_list_id', 'media_id']);
            $table->timestamp('added_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('list_media');
    }
};