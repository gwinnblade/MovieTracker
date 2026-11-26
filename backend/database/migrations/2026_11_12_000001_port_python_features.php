<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('avatar_key')->nullable();
            $table->unsignedBigInteger('legacy_id')->nullable()->unique();
        });
        Schema::table('media', function (Blueprint $table) {
            $table->unsignedBigInteger('tmdb_id')->nullable();
            $table->string('tmdb_type', 8)->nullable();
            $table->json('tmdb_data')->nullable();
            $table->timestamp('tmdb_synced_at')->nullable();
            $table->timestamp('tmdb_failed_at')->nullable();
            $table->unique(['tmdb_type', 'tmdb_id']);
        });
        Schema::table('entries', function (Blueprint $table) {
            $table->unsignedBigInteger('legacy_id')->nullable()->unique();
            $table->unsignedInteger('progress')->default(0);
            $table->unsignedInteger('seasons_watched')->default(0);
            $table->unsignedInteger('episodes_watched')->default(0);
        });
        Schema::table('user_lists', function (Blueprint $table) {
            $table->text('description')->nullable();
            $table->string('cover_key')->nullable();
            $table->unsignedBigInteger('legacy_id')->nullable()->unique();
            $table->unique(['user_id', 'name']);
        });
        Schema::table('persons', function (Blueprint $table) {
            $table->unsignedBigInteger('tmdb_id')->nullable()->unique();
        });
        Schema::table('moderation_requests', function (Blueprint $table) {
            $table->foreignId('media_id')->nullable()->constrained('media')->nullOnDelete();
            $table->foreignId('moderator_id')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('resolved_at')->nullable();
            $table->unsignedBigInteger('tmdb_id')->nullable();
            $table->string('tmdb_type', 8)->nullable();
            $table->string('action', 8)->default('create');
        });
        Schema::create('season_progress', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->foreignId('media_id')->constrained('media')->cascadeOnDelete();
            $table->unsignedSmallInteger('season');
            $table->unsignedSmallInteger('watched')->default(0);
            $table->string('status', 16)->default('watching');
            $table->unsignedBigInteger('legacy_id')->nullable()->unique();
            $table->timestamps();
            $table->unique(['user_id', 'media_id', 'season']);
        });
        Schema::create('episode_notes', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->foreignId('media_id')->constrained('media')->cascadeOnDelete();
            $table->unsignedSmallInteger('season');
            $table->unsignedSmallInteger('episode');
            $table->text('note');
            $table->unsignedBigInteger('legacy_id')->nullable()->unique();
            $table->timestamps();
            $table->unique(['user_id', 'media_id', 'season', 'episode']);
        });
        Schema::create('legacy_posts', function (Blueprint $table) {
            $table->unsignedBigInteger('id')->primary();
            $table->text('title')->nullable();
            $table->text('text')->nullable();
        });
        Schema::create('legacy_imports', function (Blueprint $table) {
            $table->string('source_hash', 64)->primary();
            $table->json('counts');
            $table->timestamp('imported_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('legacy_imports');
        Schema::dropIfExists('legacy_posts');
        Schema::dropIfExists('episode_notes');
        Schema::dropIfExists('season_progress');
        Schema::table('moderation_requests', function (Blueprint $table) {
            $table->dropConstrainedForeignId('media_id');
            $table->dropConstrainedForeignId('moderator_id');
            $table->dropColumn(['resolved_at', 'tmdb_id', 'tmdb_type', 'action']);
        });
        Schema::table('persons', function (Blueprint $table) {
            $table->dropUnique(['tmdb_id']);
            $table->dropColumn('tmdb_id');
        });
        Schema::table('user_lists', function (Blueprint $table) {
            $table->dropUnique(['user_id', 'name']);
            $table->dropUnique(['legacy_id']);
            $table->dropColumn(['description', 'cover_key', 'legacy_id']);
        });
        Schema::table('entries', function (Blueprint $table) {
            $table->dropUnique(['legacy_id']);
            $table->dropColumn(['legacy_id', 'progress', 'seasons_watched', 'episodes_watched']);
        });
        Schema::table('media', function (Blueprint $table) {
            $table->dropUnique(['tmdb_type', 'tmdb_id']);
            $table->dropColumn(['tmdb_id', 'tmdb_type', 'tmdb_data', 'tmdb_synced_at', 'tmdb_failed_at']);
        });
        Schema::table('users', function (Blueprint $table) {
            $table->dropUnique(['legacy_id']);
            $table->dropColumn(['avatar_key', 'legacy_id']);
        });
    }
};
