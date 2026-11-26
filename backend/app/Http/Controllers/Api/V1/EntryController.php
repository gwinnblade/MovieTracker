<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\Entry;
use App\Models\EpisodeEntry;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;

class EntryController extends Controller
{
    public function index(Request $request)
    {
        $data = $request->validate(['status_id' => 'nullable|integer|exists:statuses,id', 'type_id' => 'nullable|integer|exists:media_types,id',
            'rated' => 'sometimes|boolean', 'sort' => 'sometimes|in:added,rating_asc,rating_desc', 'page' => 'sometimes|integer|min:1',
            'per_page' => 'sometimes|integer|min:1|max:60']);
        $query = Entry::where('user_id', $request->user()->id)->with(['media.type', 'media.genres', 'status']);
        if (! empty($data['status_id'])) {
            $query->where('status_id', $data['status_id']);
        }
        if (! empty($data['type_id'])) {
            $query->whereHas('media', fn ($q) => $q->where('type_id', $data['type_id']));
        }
        if (! empty($data['rated'])) {
            $query->whereNotNull('rating');
        }
        $sort = $data['sort'] ?? 'added';
        if ($sort !== 'added') {
            $query->orderByRaw('rating IS NULL')->orderBy('rating', $sort === 'rating_asc' ? 'asc' : 'desc');
        }

        return response()->json($query->orderByDesc('id')->paginate($data['per_page'] ?? 20));
    }

    public function show(Request $request, int $id)
    {
        return response()->json(Entry::where('user_id', $request->user()->id)->with(['media.type', 'status', 'episodeEntries.episode'])->findOrFail($id));
    }

    public function store(Request $request)
    {
        $data = $request->validate([
            'media_id' => 'required|integer|exists:media,id', 'status_id' => 'required|integer|exists:statuses,id',
            'rating' => 'sometimes|nullable|integer|min:1|max:10', 'date' => 'sometimes|nullable|date', 'note' => 'sometimes|nullable|string|max:5000',
            'episodes' => 'sometimes|array|max:1000',
            'episodes.*.episode_id' => ['required', 'integer', 'distinct', Rule::exists('episodes', 'id')->where('media_id', $request->input('media_id'))],
            'episodes.*.watched' => 'required|boolean', 'episodes.*.rating' => 'nullable|integer|min:1|max:10', 'episodes.*.note' => 'nullable|string|max:5000',
        ]);
        $entry = DB::transaction(function () use ($request, $data) {
            $entry = Entry::updateOrCreate(['user_id' => $request->user()->id, 'media_id' => $data['media_id']],
                array_intersect_key($data, array_flip(['status_id', 'rating', 'note', 'date'])));
            foreach ($data['episodes'] ?? [] as $episode) {
                EpisodeEntry::updateOrCreate(['entry_id' => $entry->id, 'episode_id' => $episode['episode_id']],
                    ['watched' => $episode['watched'], 'rating' => $episode['rating'] ?? null, 'note' => $episode['note'] ?? null]);
            }

            return $entry;
        });

        return response()->json($entry->load(['media.type', 'status', 'episodeEntries.episode']), 201);
    }

    public function destroy(Request $request, int $id)
    {
        Entry::where('user_id', $request->user()->id)->findOrFail($id)->delete();

        return response()->json(['message' => 'Запись удалена из личного списка.']);
    }
}
