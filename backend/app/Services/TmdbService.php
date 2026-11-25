<?php

namespace App\Services;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Symfony\Component\HttpKernel\Exception\HttpException;

class TmdbService
{
    private function request(string $path, array $params = [], int $ttl = 1800): array
    {
        $token = (string) config('services.tmdb.api_key');
        if ($token === '') {
            throw new HttpException(503, 'Добавьте TMDB_API_KEY в backend/.env и перезапустите сервер.');
        }
        $params = array_merge(['language' => 'ru-RU'], $params);

        return Cache::remember('tmdb:'.hash('sha256', $path.json_encode($params)), $ttl, function () use ($path, $params, $token) {
            try {
                $response = Http::withToken($token)->acceptJson()->connectTimeout(5)->timeout(18)
                    ->get('https://api.themoviedb.org/3/'.$path, $params);
            } catch (ConnectionException $e) {
                throw new HttpException(503, 'Нет соединения с TMDB. Проверьте VPN и настройки DNS.');
            }
            if ($response->status() === 404) {
                throw new HttpException(404, 'Этот фильм или сериал не найден в TMDB.');
            }
            if (in_array($response->status(), [401, 403], true)) {
                throw new HttpException(503, 'TMDB отклонил токен. Проверьте TMDB API Read Access Token в backend/.env.');
            }
            if (! $response->successful()) {
                throw new HttpException(503, 'TMDB временно недоступен. Попробуйте позже.');
            }

            return $response->json();
        });
    }

    private function title(array $data, string $type): array
    {
        return [
            'tmdb_id' => $data['id'], 'tmdb_type' => $type, 'media_type' => $type,
            'title_ru' => $data['title'] ?? $data['name'] ?? '',
            'title_en' => $data['original_title'] ?? $data['original_name'] ?? '',
            'original_title' => $data['original_title'] ?? $data['original_name'] ?? '',
            'description_ru' => $data['overview'] ?? '', 'overview' => $data['overview'] ?? '',
            'release_date' => ($data['release_date'] ?? $data['first_air_date'] ?? '') ?: null,
            'poster_key' => $data['poster_path'] ?? null,
            'poster_url' => empty($data['poster_path']) ? null : '/tmdb-images/w500'.$data['poster_path'],
            'backdrop_url' => empty($data['backdrop_path']) ? null : '/tmdb-images/w1280'.$data['backdrop_path'],
            'vote_average' => round((float) ($data['vote_average'] ?? 0), 1),
            'type' => ['code' => $type === 'tv' ? 'series' : 'movie', 'name_ru' => $type === 'tv' ? 'Сериал' : 'Фильм'],
        ];
    }

    private function page(array $data, ?string $type): array
    {
        $items = [];
        foreach ($data['results'] ?? [] as $item) {
            $kind = $type ?? ($item['media_type'] ?? 'movie');
            if (in_array($kind, ['movie', 'tv'], true)) {
                $items[] = $this->title($item, $kind);
            }
        }

        return ['data' => $items, 'current_page' => $data['page'] ?? 1,
            'last_page' => min(500, $data['total_pages'] ?? 1),
            'total' => $data['total_results'] ?? count($items), 'per_page' => 20];
    }

    public function search(string $query, string $type = 'all', int $page = 1): array
    {
        return $this->page($this->request('search/'.($type === 'all' ? 'multi' : $type), [
            'query' => $query, 'include_adult' => 'false', 'page' => $page,
        ]), $type === 'all' ? null : $type);
    }

    public function trending(string $type = 'all', int $page = 1): array
    {
        return $this->page($this->request('trending/'.$type.'/week', ['page' => $page]), $type === 'all' ? null : $type);
    }

    public function details(string $type, int $id): array
    {
        $data = $this->request($type.'/'.$id, ['append_to_response' => 'credits'], 86400);
        $person = fn (array $p) => ['tmdb_id' => $p['id'], 'name' => $p['name'], 'character' => $p['character'] ?? null,
            'profile_path' => $p['profile_path'] ?? null,
            'photo_url' => empty($p['profile_path']) ? null : '/tmdb-images/w185'.$p['profile_path']];
        $directors = array_values(array_filter($data['credits']['crew'] ?? [], fn ($p) => ($p['job'] ?? '') === 'Director'));
        if ($type === 'tv' && ! $directors) {
            $directors = $data['created_by'] ?? [];
        }

        return array_merge($this->title($data, $type), [
            'cast' => array_map($person, array_slice($data['credits']['cast'] ?? [], 0, 12)),
            'directors' => array_map($person, $directors), 'director' => isset($directors[0]) ? $person($directors[0]) : null,
            'companies' => array_map(fn ($c) => ['name' => $c['name']], $data['production_companies'] ?? []),
            'genres' => array_map(fn ($g) => ['tmdb_id' => $g['id'], 'name_ru' => $g['name'], 'name_en' => $g['name']], $data['genres'] ?? []),
            'runtime' => $data['runtime'] ?? null, 'number_of_episodes' => $data['number_of_episodes'] ?? null,
            'seasons' => array_map(fn ($s) => ['season' => $s['season_number'], 'name' => $s['name'], 'episode_count' => $s['episode_count'],
                'poster_url' => empty($s['poster_path']) ? null : '/tmdb-images/w185'.$s['poster_path']], $data['seasons'] ?? []),
        ]);
    }

    public function season(int $id, int $season): array
    {
        $data = $this->request('tv/'.$id.'/season/'.$season, [], 86400);

        return ['season' => $data['season_number'], 'name' => $data['name'],
            'episodes' => array_map(fn ($e) => ['number' => $e['episode_number'], 'season' => $e['season_number'],
                'title' => $e['name'], 'description_ru' => $e['overview'] ?? '',
                'air_date' => ($e['air_date'] ?? '') ?: null, 'duration' => $e['runtime'] ?? null], $data['episodes'] ?? [])];
    }
}
