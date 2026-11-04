<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
 {
        Schema::table('moderation_requests', function (Blueprint $table) {
            $table->json('tmdb_data')->nullable()->after('poster_key');
        });
    }

    public function down(): void
    {
        Schema::table('moderation_requests', function (Blueprint $table) {
            $table->dropColumn('tmdb_data');
        });
    }
};