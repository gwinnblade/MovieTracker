<?php

namespace App\Services;

use App\Models\Company;
use App\Models\Genre;
use App\Models\Media;
use App\Models\Person;
use App\Models\Role;
use App\Models\Type;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpKernel\Exception\HttpException;

class MediaLibrary
{
    public function __construct(private TmdbService $tmdb) {}

    public function external(string $type, int $id): Media
    {
        $media = Media::where('tmdb_type', $type)->where('tmdb_id', $id)->first();
        if ($media) {
            return $this->refresh($media);
        }
        $details = $this->tmdb->details($type, $id);

        return DB::transaction(function () use ($type, $id, $details) {
            $media = Media::firstOrCreate(['tmdb_type' => $type, 'tmdb_id' => $id], [
                'type_id' => Type::where('code', $type === 'tv' ? 'series' : 'movie')->value('id'),
                'title_ru' => $details['title_ru'], 'moderation_status' => 'external']);

            return $this->apply($media, $details);
        });
    }

    public function refresh(Media $media): Media
    {
        if (! $media->tmdb_id || ($media->tmdb_synced_at && $media->tmdb_synced_at->isAfter(now()->subDay()))
            || ($media->tmdb_failed_at && $media->tmdb_failed_at->isAfter(now()->subHour()))) {
            return $media;
        }
        try {
            return $this->apply($media, $this->tmdb->details($media->tmdb_type, $media->tmdb_id));
        } catch (HttpException $e) {
            $media->update(['tmdb_failed_at' => now()]);

            return $media;
        }
    }

    public function apply(Media $media, array $data, bool $publish = false): Media
    {
        $fields = ['tmdb_data' => $data, 'tmdb_synced_at' => now(), 'tmdb_failed_at' => null];
        if ($media->moderation_status !== 'approved' || $publish) {
            foreach (['title_ru', 'title_en', 'original_title', 'description_ru', 'release_date', 'poster_key'] as $field) {
                $fields[$field] = $data[$field] ?? null;
            }
        }
        $media->update($fields);
        if ($media->moderation_status !== 'approved' || $publish) {
            $genreIds = [];
            foreach ($data['genres'] ?? [] as $genre) {
                $name = mb_strtoupper(mb_substr($genre['name_ru'], 0, 1)).mb_substr($genre['name_ru'], 1);
                $genreIds[] = Genre::firstOrCreate(['name_ru' => $name], ['name_en' => $genre['name_en'] ?? $name])->id;
            }
            $media->genres()->sync($genreIds);
        }
        if ($publish) {
            $this->credits($media, $data);
        }

        return $media;
    }

    public function credits(Media $media, array $data): void
    {
        $media->persons()->detach();
        foreach (['directors' => 'director', 'cast' => 'cast'] as $key => $code) {
            $role = Role::where('code', $code)->firstOrFail();
            $people = $data[$key] ?? ($key === 'directors' && ! empty($data['director']) ? [$data['director']] : []);
            $attached = [];
            foreach ($people as $item) {
                if (empty($item['name'])) {
                    continue;
                }
                $person = ! empty($item['tmdb_id'])
                    ? Person::firstOrCreate(['tmdb_id' => $item['tmdb_id']], ['name' => $item['name']])
                    : Person::firstOrCreate(['name' => $item['name']]);
                if (! empty($item['profile_path'])) {
                    $path = parse_url($item['profile_path'], PHP_URL_PATH);
                    $path = preg_replace('#^/t/p/[^/]+#', '', $path ?? '');
                    if (preg_match('#^/[A-Za-z0-9_.-]+$#', $path)) {
                        $person->update(['photo_key' => $path]);
                    }
                }
                if (! isset($attached[$person->id])) {
                    $media->persons()->attach($person->id, ['role_id' => $role->id, 'character' => $item['character'] ?? null]);
                    $attached[$person->id] = true;
                }
            }
        }
        $media->companies()->detach();
        $roleId = Role::where('code', 'production')->value('id');
        foreach ($data['companies'] ?? [] as $item) {
            if (! empty($item['name'])) {
                $company = Company::firstOrCreate(['name' => $item['name']]);
                $media->companies()->syncWithoutDetaching([$company->id => ['role_id' => $roleId]]);
            }
        }
    }

    public function serialize(Media $media): array
    {
        $media->load(['type', 'genres', 'persons', 'companies', 'episodes']);
        $roles = Role::all()->keyBy('id');
        $data = $media->toArray();
        unset($data['tmdb_data']);
        $data['persons'] = $media->persons->map(function ($person) use ($roles) {
            return ['id' => $person->id, 'tmdb_id' => $person->tmdb_id, 'name' => $person->name,
                'photo_url' => $person->photo_key ? (str_starts_with($person->photo_key, '/') ? '/tmdb-images/w185'.$person->photo_key : '/storage/'.$person->photo_key) : null,
                'pivot' => $person->pivot->toArray(), 'roles' => [$roles[$person->pivot->role_id]]];
        })->values()->all();
        foreach (['cast', 'directors', 'director', 'seasons', 'runtime', 'vote_average', 'number_of_episodes', 'backdrop_url'] as $field) {
            $data[$field] = $media->tmdb_data[$field] ?? ($field === 'seasons' ? [] : null);
        }

        return $data;
    }
}
