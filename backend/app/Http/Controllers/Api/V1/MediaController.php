<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\Media;
use App\Models\Role;
use App\Services\MediaLibrary;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class MediaController extends Controller
{
    public function __construct(private MediaLibrary $library) {}

    public function index(Request $request)
    {
        $data = $request->validate([
            'search' => 'nullable|string|max:150', 'type_id' => 'nullable|integer|exists:media_types,id',
            'genre_ids' => 'nullable|string|max:200', 'year_from' => 'nullable|integer|min:1800|max:2200',
            'year_to' => 'nullable|integer|min:1800|max:2200', 'sort_by' => 'sometimes|in:release_date,title_ru,avg_rating,created_at',
            'sort_order' => 'sometimes|in:asc,desc', 'per_page' => 'sometimes|integer|min:1|max:60', 'page' => 'sometimes|integer|min:1',
        ]);
        $query = Media::with(['type', 'genres'])->withAvg('entries as avg_rating', 'rating')->where('moderation_status', 'approved');
        if (! empty($data['search'])) {
            $terms = preg_split('/[^\p{L}\p{N}]+/u', trim($data['search']), -1, PREG_SPLIT_NO_EMPTY);
            if ($terms) {
                $match = implode(' AND ', array_map(fn ($term) => '"'.$term.'"*', $terms));
                $query->whereIn('id', DB::table('media_fts')->select('rowid')->whereRaw('media_fts MATCH ?', [$match]));
            }
        }
        if (! empty($data['type_id'])) {
            $query->where('type_id', $data['type_id']);
        }
        if (! empty($data['year_from'])) {
            $query->whereYear('release_date', '>=', $data['year_from']);
        }
        if (! empty($data['year_to'])) {
            $query->whereYear('release_date', '<=', $data['year_to']);
        }
        foreach (array_filter(explode(',', $data['genre_ids'] ?? '')) as $genre) {
            $query->whereHas('genres', fn ($q) => $q->where('genres.id', (int) $genre));
        }

        return response()->json($query->orderBy($data['sort_by'] ?? 'created_at', $data['sort_order'] ?? 'desc')->orderByDesc('id')->paginate($data['per_page'] ?? 18));
    }

    public function show(int $id)
    {
        return response()->json($this->library->serialize($this->library->refresh(Media::findOrFail($id))));
    }

    public function random(Request $request)
    {
        $data = $request->validate(['type_id' => 'nullable|integer|exists:media_types,id', 'genre_id' => 'nullable|integer|exists:genres,id']);
        $query = Media::where('moderation_status', 'approved');
        if (! empty($data['type_id'])) {
            $query->where('type_id', $data['type_id']);
        }
        if (! empty($data['genre_id'])) {
            $query->whereHas('genres', fn ($q) => $q->where('genres.id', $data['genre_id']));
        }
        $media = $query->inRandomOrder()->first();
        abort_unless($media, 404, 'В каталоге пока нет подходящих одобренных фильмов.');

        return response()->json($this->library->serialize($media));
    }

    public function similar(int $id)
    {
        $media = Media::findOrFail($id);
        $roleId = Role::where('code', 'director')->value('id');
        $director = $media->persons()->wherePivot('role_id', $roleId)->first();
        $movies = $director ? $director->media()->wherePivot('role_id', $roleId)->where('media.id', '!=', $id)
            ->where('moderation_status', 'approved')->with('type')->orderByDesc('release_date')->limit(12)->get() : [];

        return response()->json(['director' => $director ? ['id' => $director->id, 'name' => $director->name] : null, 'movies' => $movies]);
    }
}
