<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('moderation_requests', function (Blueprint $table) {
            $table->string('poster_key')->nullable()->after('description_ru');
        });
    }

    public function down(): void
    {
        Schema::table('moderation_requests', function (Blueprint $table) {
            $table->dropColumn('poster_key');
        });
    }
};