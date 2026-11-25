<?php

namespace App\Console\Commands;

use App\Models\Media;
use App\Models\Status;
use App\Models\Type;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PDO;

class ImportLegacy extends Command
{
    protected $signature = 'legacy:import {source : Read-only Flask SQLite database}';

    protected $description = 'Import Flask accounts, ratings, collections and TV notes without changing the source.';

    public function handle(): int
    {
        $path = realpath($this->argument('source'));
        if (! $path || ! is_file($path)) {
            $this->error('Source SQLite database does not exist.');

            return self::FAILURE;
        }
        if ($path === realpath(config('database.connections.sqlite.database'))) {
            $this->error('The source and destination must be different databases.');

            return self::FAILURE;
        }
        $hash = hash_file('sha256', $path);
        if (DB::table('legacy_imports')->where('source_hash', $hash)->exists()) {
            $this->info('This source has already been imported. No data changed.');

            return self::SUCCESS;
        }
        $source = new PDO('sqlite:'.$path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::SQLITE_ATTR_OPEN_FLAGS => PDO::SQLITE_OPEN_READONLY, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
        foreach (['user', 'user_media', 'collection', 'collection_item', 'episode_note', 'tv_season_progress', 'post'] as $table) {
            if (! $source->query("SELECT name FROM sqlite_master WHERE type='table' AND name='$table'")->fetch()) {
                $this->error('Unsupported source schema: missing '.$table);

                return self::FAILURE;
            }
        }
        $this->call('db:seed', ['--class' => 'DictionarySeeder', '--force' => true]);
        $counts = DB::transaction(function () use ($source, $hash) {
            $users = [];
            $lists = [];
            $mediaIds = [];
            $counts = [];
            $now = now()->format('Y-m-d H:i:s');
            foreach ($source->query('SELECT * FROM user ORDER BY id') as $row) {
                $existing = DB::table('users')->where('legacy_id', $row['id'])->first();
                if (! $existing) {
                    if (DB::table('users')->where('login', $row['username'])->orWhere('email', $row['email'])->exists()) {
                        throw new \RuntimeException('An account with the same login/email already exists. Import into an empty database first.');
                    }
                    $avatar = $this->uploadKey($row['avatar_url']);
                    $id = DB::table('users')->insertGetId([
                        'legacy_id' => $row['id'], 'login' => $row['username'], 'name' => $row['username'], 'email' => $row['email'],
                        'password' => $row['password_hash'], 'role' => 'user', 'language' => 'ru', 'theme' => 'dark',
                        'avatar_key' => $avatar, 'created_at' => $row['created_at'] ?: $now, 'updated_at' => $row['created_at'] ?: $now,
                    ]);
                } else {
                    $id = $existing->id;
                }
                $users[$row['id']] = $id;
            }
            $counts['users'] = count($users);
            $types = Type::pluck('id', 'code');
            $statuses = Status::pluck('id', 'code');
            $titles = $source->query("SELECT media_type,tmdb_id FROM user_media UNION SELECT media_type,tmdb_id FROM collection_item UNION SELECT 'tv',tv_id FROM episode_note UNION SELECT 'tv',tv_id FROM tv_season_progress");
            foreach ($titles as $row) {
                $kind = $row['media_type'];
                if (! in_array($kind, ['movie', 'tv'], true)) {
                    throw new \RuntimeException('Unknown source media type.');
                }
                $media = Media::firstOrCreate(['tmdb_type' => $kind, 'tmdb_id' => $row['tmdb_id']], [
                    'type_id' => $types[$kind === 'tv' ? 'series' : 'movie'],
                    'title_ru' => ($kind === 'tv' ? 'Сериал' : 'Фильм').' TMDB #'.$row['tmdb_id'], 'moderation_status' => 'external',
                ]);
                $mediaIds[$kind.':'.$row['tmdb_id']] = $media->id;
            }
            $counts['tmdb_titles'] = count($mediaIds);
            $counts['entries'] = 0;
            foreach ($source->query('SELECT * FROM user_media ORDER BY id') as $row) {
                DB::table('entries')->insertOrIgnore([
                    'legacy_id' => $row['id'], 'user_id' => $users[$row['user_id']], 'media_id' => $mediaIds[$row['media_type'].':'.$row['tmdb_id']],
                    'status_id' => $statuses[$row['status'] ?: 'untracked'], 'rating' => $row['rating'], 'note' => $row['note'],
                    'progress' => $row['progress'] ?? 0, 'seasons_watched' => $row['seasons_watched'] ?? 0, 'episodes_watched' => $row['episodes_watched'] ?? 0,
                    'created_at' => $now, 'updated_at' => $now,
                ]);
                $counts['entries']++;
            }
            foreach ($source->query('SELECT * FROM collection ORDER BY id') as $row) {
                $existing = DB::table('user_lists')->where('legacy_id', $row['id'])->first();
                $id = $existing?->id ?? DB::table('user_lists')->insertGetId([
                    'legacy_id' => $row['id'], 'user_id' => $users[$row['user_id']], 'name' => $row['title'], 'description' => $row['description'],
                    'cover_key' => $this->uploadKey($row['cover_url']), 'is_public' => (bool) $row['is_public'],
                    'share_token' => $row['is_public'] ? Str::random(40) : null,
                    'created_at' => $row['created_at'] ?: $now, 'updated_at' => $row['updated_at'] ?: $now,
                ]);
                $lists[$row['id']] = $id;
            }
            $counts['collections'] = count($lists);
            $counts['collection_items'] = 0;
            foreach ($source->query('SELECT * FROM collection_item ORDER BY id') as $row) {
                DB::table('list_media')->insertOrIgnore(['user_list_id' => $lists[$row['collection_id']],
                    'media_id' => $mediaIds[$row['media_type'].':'.$row['tmdb_id']], 'added_at' => $row['created_at'] ?: $now]);
                $counts['collection_items']++;
            }
            $counts['season_progress'] = 0;
            foreach ($source->query('SELECT * FROM tv_season_progress ORDER BY id') as $row) {
                DB::table('season_progress')->insertOrIgnore(['legacy_id' => $row['id'], 'user_id' => $users[$row['user_id']],
                    'media_id' => $mediaIds['tv:'.$row['tv_id']], 'season' => $row['season'], 'watched' => $row['watched'],
                    'status' => $row['status'] ?: 'untracked', 'created_at' => $row['updated_at'] ?: $now, 'updated_at' => $row['updated_at'] ?: $now]);
                $counts['season_progress']++;
            }
            $counts['episode_notes'] = 0;
            foreach ($source->query('SELECT * FROM episode_note ORDER BY id') as $row) {
                DB::table('episode_notes')->insertOrIgnore(['legacy_id' => $row['id'], 'user_id' => $users[$row['user_id']],
                    'media_id' => $mediaIds['tv:'.$row['tv_id']], 'season' => $row['season'], 'episode' => $row['episode'], 'note' => $row['note'],
                    'created_at' => $row['created_at'] ?: $now, 'updated_at' => $row['updated_at'] ?: $now]);
                $counts['episode_notes']++;
            }
            $counts['archived_posts'] = 0;
            foreach ($source->query('SELECT * FROM post ORDER BY id') as $row) {
                DB::table('legacy_posts')->insertOrIgnore($row);
                $counts['archived_posts']++;
            }
            DB::table('legacy_imports')->insert(['source_hash' => $hash, 'counts' => json_encode($counts), 'imported_at' => $now]);

            return $counts;
        });
        if (! hash_equals($hash, hash_file('sha256', $path))) {
            throw new \RuntimeException('Source database changed during import.');
        }
        $this->table(['Data', 'Source records'], array_map(fn ($key, $value) => [$key, $value], array_keys($counts), $counts));
        $this->info('Import complete. Original SQLite file is unchanged. TMDB metadata is fetched when a title is opened.');

        return self::SUCCESS;
    }

    private function uploadKey(?string $path): ?string
    {
        if (! $path) {
            return null;
        }
        if (str_starts_with($path, '/static/uploads/')) {
            return 'legacy/'.basename($path);
        }

        return $path;
    }
}
