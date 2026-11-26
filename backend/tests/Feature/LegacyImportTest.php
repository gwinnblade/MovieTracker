<?php

namespace Tests\Feature;

use App\Models\Entry;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use PDO;
use Tests\TestCase;
use Tests\Unit\LegacyPasswordTest;

class LegacyImportTest extends TestCase
{
    use RefreshDatabase;

    public function test_import_preserves_relationships_passwords_and_is_idempotent(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'rewatch-legacy-');
        try {
            $source = new PDO('sqlite:'.$path);
            $source->exec('CREATE TABLE user (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password_hash TEXT, created_at TEXT, avatar_url TEXT);
                CREATE TABLE user_media (id INTEGER PRIMARY KEY, user_id INTEGER, media_type TEXT, tmdb_id INTEGER, rating INTEGER, progress INTEGER, note TEXT, status TEXT, seasons_watched INTEGER, episodes_watched INTEGER);
                CREATE TABLE collection (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, description TEXT, cover_url TEXT, is_public INTEGER, created_at TEXT, updated_at TEXT);
                CREATE TABLE collection_item (id INTEGER PRIMARY KEY, collection_id INTEGER, media_type TEXT, tmdb_id INTEGER, created_at TEXT);
                CREATE TABLE episode_note (id INTEGER PRIMARY KEY, user_id INTEGER, tv_id INTEGER, season INTEGER, episode INTEGER, note TEXT, created_at TEXT, updated_at TEXT);
                CREATE TABLE tv_season_progress (id INTEGER PRIMARY KEY, user_id INTEGER, tv_id INTEGER, season INTEGER, watched INTEGER, status TEXT, updated_at TEXT);
                CREATE TABLE post (id INTEGER PRIMARY KEY, title TEXT, text TEXT);');
            $source->prepare('INSERT INTO user VALUES (7,?,?,?,?,?)')->execute(['legacy-user', 'legacy@example.test', LegacyPasswordTest::HASH, '2025-01-01 10:00:00', '/static/uploads/avatar.png']);
            $source->exec("INSERT INTO user_media VALUES (9,7,'tv',1396,8,2,'Личная заметка','watching',1,9);
                INSERT INTO collection VALUES (5,7,'Любимые сериалы','Для выходных',NULL,1,'2025-01-01','2025-01-02');
                INSERT INTO collection_item VALUES (2,5,'tv',1396,'2025-01-02');
                INSERT INTO episode_note VALUES (4,7,1396,1,2,'Вторая серия','2025-01-02','2025-01-03');
                INSERT INTO tv_season_progress VALUES (3,7,1396,1,2,'watching','2025-01-03');
                INSERT INTO post VALUES (1,'Архив','Текст');");
            $source = null;
            $checksum = hash_file('sha256', $path);
            $this->artisan('legacy:import', ['source' => $path])->assertSuccessful();
            $this->assertSame($checksum, hash_file('sha256', $path));
            $user = User::where('legacy_id', 7)->firstOrFail();
            $entry = Entry::where('legacy_id', 9)->firstOrFail();
            $this->assertSame($user->id, $entry->user_id);
            $this->assertSame(1396, $entry->media->tmdb_id);
            $this->assertSame('tv', $entry->media->tmdb_type);
            $this->assertSame('external', $entry->media->moderation_status);
            $this->assertSame('watching', $entry->status->code);
            $this->assertSame('Личная заметка', $entry->note);
            $this->assertSame(LegacyPasswordTest::HASH, $user->getAuthPassword());
            $this->assertDatabaseHas('episode_notes', ['user_id' => $user->id, 'media_id' => $entry->media_id, 'note' => 'Вторая серия']);
            $this->assertDatabaseHas('season_progress', ['user_id' => $user->id, 'media_id' => $entry->media_id, 'watched' => 2]);
            $list = $user->lists()->firstOrFail();
            $this->assertTrue($list->is_public);
            $this->assertNotEmpty($list->share_token);
            $this->assertSame($entry->media_id, $list->media()->first()->id);
            $entry->update(['note' => 'Новая заметка']);
            $this->artisan('legacy:import', ['source' => $path])->assertSuccessful();
            $this->assertDatabaseCount('entries', 1);
            $this->assertDatabaseCount('episode_notes', 1);
            $this->assertDatabaseCount('list_media', 1);
            $this->assertDatabaseHas('entries', ['id' => $entry->id, 'note' => 'Новая заметка']);
            $this->withHeaders(['Origin' => 'http://localhost:3002', 'Referer' => 'http://localhost:3002/']);
            $this->postJson('/api/v1/auth/login', ['login' => 'legacy-user', 'password' => 'wrong'])->assertUnprocessable();
            $this->postJson('/api/v1/auth/login', ['login' => 'legacy-user', 'password' => 'TestPassword2026!'])->assertOk()->assertJsonPath('id', $user->id);
            $this->assertTrue(Hash::check('TestPassword2026!', $user->fresh()->getAuthPassword()));
            $this->getJson('/api/v1/auth/me')->assertOk()->assertJsonPath('id', $user->id);
            $this->assertSame($checksum, hash_file('sha256', $path));
        } finally {
            @unlink($path);
        }
    }
}
