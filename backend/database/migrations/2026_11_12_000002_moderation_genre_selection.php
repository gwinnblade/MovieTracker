<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('moderation_requests', fn (Blueprint $table) => $table->boolean('genres_provided')->default(false));
        DB::statement("CREATE UNIQUE INDEX moderation_pending_tmdb ON moderation_requests (tmdb_type, tmdb_id) WHERE status = 'pending' AND action = 'create' AND tmdb_id IS NOT NULL");
    }

    public function down(): void
    {
        DB::statement('DROP INDEX IF EXISTS moderation_pending_tmdb');
        Schema::table('moderation_requests', fn (Blueprint $table) => $table->dropColumn('genres_provided'));
    }
};
