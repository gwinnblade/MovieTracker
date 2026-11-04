<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('person_media', function (Blueprint $table) {
            $table->string('character')->nullable()->after('role_id');
        });
    }

    public function down(): void
    {
        Schema::table('person_media', function (Blueprint $table) {
            $table->dropColumn('character');
        });
    }
};