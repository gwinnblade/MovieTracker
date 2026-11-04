<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Services\TmdbService;
use Illuminate\Http\Request;

class TmdbController extends Controller
{
    protected TmdbService $tmdbService;

    public function __construct(TmdbService $tmdbService)
    {
        $this->tmdbService = $tmdbService;
    }

    public function search(Request $request)
    {
        $request->validate([
            'query' => 'required|string|min:2|max:100',
        ]);
        
        $results = $this->tmdbService->searchMovie($request->query('query'));

        return response()->json($results);
    }

    public function details(Request $request)
    {
        $request->validate([
            'tmdb_id' => 'required|integer',
        ]);

        $details = $this->tmdbService->getMovieDetails((int) $request->query('tmdb_id'));

        return response()->json($details);
    }
}