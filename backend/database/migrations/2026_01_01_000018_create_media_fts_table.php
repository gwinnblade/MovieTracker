<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::statement("
            CREATE VIRTUAL TABLE media_fts USING fts5(
                title_ru,
                title_en,
                original_title,
                content='media',
                content_rowid='id',
                tokenize='unicode61'
            );
        ");

        DB::statement("
            CREATE TRIGGER media_ai AFTER INSERT ON media BEGIN
                INSERT INTO media_fts(rowid, title_ru, title_en, original_title)
                VALUES (new.id, new.title_ru, new.title_en, new.original_title);
            END;
        ");

        DB::statement("
            CREATE TRIGGER media_ad AFTER DELETE ON media BEGIN
                INSERT INTO media_fts(media_fts, rowid, title_ru, title_en, original_title)
                VALUES ('delete', old.id, old.title_ru, old.title_en, old.original_title);
            END;
        ");

        DB::statement("
            CREATE TRIGGER media_au AFTER UPDATE ON media BEGIN
                INSERT INTO media_fts(media_fts, rowid, title_ru, title_en, original_title)
                VALUES ('delete', old.id, old.title_ru, old.title_en, old.original_title);
                INSERT INTO media_fts(rowid, title_ru, title_en, original_title)
                VALUES (new.id, new.title_ru, new.title_en, new.original_title);
            END;
        ");
    }

    public function down(): void
    {
        DB::statement('DROP TRIGGER IF EXISTS media_au;');
        DB::statement('DROP TRIGGER IF EXISTS media_ad;');
        DB::statement('DROP TRIGGER IF EXISTS media_ai;');
        DB::statement('DROP TABLE IF EXISTS media_fts;');
    }
};