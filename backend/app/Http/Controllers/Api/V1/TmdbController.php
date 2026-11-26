<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\Media;
use App\Services\MediaLibrary;
use App\Services\TmdbService;
use Illuminate\Http\Request;

class TmdbController extends Controller
{
    public function __construct(private TmdbService $tmdb, private MediaLibrary $library) {}

    public function search(Request $request)
    {
        $data = $request->validate(['query' => 'required|string|min:2|max:150', 'type' => 'sometimes|in:all,movie,tv', 'page' => 'sometimes|integer|min:1|max:500']);

        return response()->json($this->tmdb->search($data['query'], $data['type'] ?? 'all', $data['page'] ?? 1));
    }

    public function trending(Request $request)
    {
        $data = $request->validate(['type' => 'sometimes|in:all,movie,tv', 'page' => 'sometimes|integer|min:1|max:500']);

        return response()->json($this->tmdb->trending($data['type'] ?? 'all', $data['page'] ?? 1));
    }

    public function details(Request $request)
    {
        $data = $request->validate(['tmdb_id' => 'required|integer|min:1', 'type' => 'sometimes|in:movie,tv']);
        $type = $data['type'] ?? 'movie';
        $details = $this->tmdb->details($type, $data['tmdb_id']);
        $media = Media::where('tmdb_type', $type)->where('tmdb_id', $data['tmdb_id'])->first();
        if ($media) {
            $this->library->apply($media, $details);
            $details['id'] = $media->id;
            $details['moderation_status'] = $media->moderation_status;
        }

        return response()->json($details);
    }

    public function season(Request $request, int $id, int $season)
    {
        abort_if($id < 1 || $season < 0 || $season > 1000, 404);

        return response()->json($this->tmdb->season($id, $season));
    }

    public function save(Request $request)
    {
        $data = $request->validate(['tmdb_id' => 'required|integer|min:1', 'tmdb_type' => 'required|in:movie,tv']);

        return response()->json($this->library->serialize($this->library->external($data['tmdb_type'], $data['tmdb_id'])));
    }
}
