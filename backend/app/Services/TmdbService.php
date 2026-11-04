<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class TmdbService
{
    protected string $apiKey;
    protected string $baseUrl = 'https://api.themoviedb.org/3';
    protected string $imageBaseUrl = 'https://image.tmdb.org/t/p/w500';

    public function __construct()
    {
        $this->apiKey = config('services.tmdb.api_key');
    }

    public function searchMovie(string $query): array
    {
        if (empty($query) || strlen($query) < 2) {
            return [];
        }

        try {
            
            $response = Http::withToken($this->apiKey)
            ->withOptions(['verify' => false]) 
            ->get("{$this->baseUrl}/search/movie", [
                'query' => $query,
                'language' => 'ru-RU', 
                'include_adult' => false,
            ]);

            if ($response->successful()) {
                $data = $response->json();

                return collect($data['results'] ?? [])
                    ->take(5) 
                    ->map(function ($movie) {
                        return [
                            'tmdb_id' => $movie['id'],
                            'title_ru' => $movie['title'] ?? $movie['original_title'],
                            'title_en' => $movie['original_title'],
                            'release_date' => $movie['release_date'],
                            'overview' => $movie['overview'] ?? '',
                            'poster_url' => $movie['poster_path'] 
                                ? $this->imageBaseUrl . $movie['poster_path'] 
                                : null,
                            'vote_average' => round($movie['vote_average'], 1),
                        ];
                    })
                    ->toArray();
            }
        } catch (\Exception $e) {
            Log::error('TMDB Search Error: ' . $e->getMessage());
        }

        return [];
    }

    public function getMovieDetails(int $tmdbId): array
    {
        try {
            $response = Http::withToken($this->apiKey)
                ->withOptions(['verify' => false]) 
                ->get("{$this->baseUrl}/movie/{$tmdbId}", [
                    'language' => 'ru-RU',
                    'append_to_response' => 'credits,production_companies',
                ]);

            if ($response->successful()) {
                $data = $response->json();
                $credits = $data['credits'] ?? [];
                $companies = $data['production_companies'] ?? [];

                $cast = collect($credits['cast'] ?? [])
                    ->take(5)
                    ->map(fn($actor) => [
                        'tmdb_id' => $actor['id'],
                        'name' => $actor['name'],
                        'character' => $actor['character'] ?? '',
                        'profile_path' => $actor['profile_path'] 
                            ? $this->imageBaseUrl . $actor['profile_path'] 
                            : null,
                    ])
                    ->values()
                    ->toArray();

                $director = null;
                foreach ($credits['crew'] ?? [] as $member) {
                    if ($member['job'] === 'Director') {
                        $director = [
                            'tmdb_id' => $member['id'],
                            'name' => $member['name'],
                            'profile_path' => $member['profile_path'] 
                                ? $this->imageBaseUrl . $member['profile_path'] 
                                : null,
                        ];
                        break;
                    }
                }

                $companiesList = collect($companies)
                    ->map(fn($company) => [
                        'name' => $company['name'],
                    ])
                    ->values()
                    ->toArray();

                return [
                    'cast' => $cast,
                    'director' => $director,
                    'companies' => $companiesList,
                ];
            }
        } catch (\Exception $e) {
            Log::error('TMDB Details Error: ' . $e->getMessage());
        }

        return [];
    }
}