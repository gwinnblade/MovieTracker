<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('company_media', function (Blueprint $table) {
            $table->foreignId('media_id')->index()->constrained('media')->cascadeOnDelete();
            $table->foreignId('company_id')->index()->constrained('companies')->cascadeOnDelete();
            $table->foreignId('role_id')->index()->constrained('roles')->cascadeOnDelete();
            $table->primary(['media_id', 'company_id', 'role_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('company_media');
    }
};