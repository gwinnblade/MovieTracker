<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\Media;
use App\Models\ModerationRequest;
use App\Services\MediaLibrary;
use App\Services\TmdbService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ModerationController extends Controller
{
    public function __construct(private TmdbService $tmdb, private MediaLibrary $library) {}

    public function index(Request $request)
    {
        $data = $request->validate(['status' => 'sometimes|in:pending,approved,rejected']);
        $query = ModerationRequest::with(['user:id,name,login', 'type', 'genres']);
        if (! $request->user()->isModerator()) {
            $query->where('user_id', $request->user()->id);
        }
        if (! empty($data['status'])) {
            $query->where('status', $data['status']);
        }

        return response()->json($query->latest()->get());
    }

    public function store(Request $request)
    {
        $data = $request->validate([
            'title_ru' => 'required|string|max:255', 'title_en' => 'nullable|string|max:255',
            'type_id' => 'required|exists:media_types,id', 'release_year' => 'nullable|integer|min:1800|max:2200',
            'description_ru' => 'nullable|string|max:10000', 'poster' => 'nullable|image|mimes:jpeg,jpg,png,webp|max:5120',
            'genre_ids' => 'sometimes|array|max:30', 'genre_ids.*' => 'integer|exists:genres,id',
            'tmdb_id' => 'nullable|integer|min:1', 'tmdb_type' => 'required_with:tmdb_id|nullable|in:movie,tv',
            'media_id' => 'nullable|integer|exists:media,id',
            'clear_genres' => 'sometimes|boolean',
        ]);
        $existing = ! empty($data['media_id']) ? Media::findOrFail($data['media_id']) : null;
        if ($existing) {
            abort_unless($existing->moderation_status === 'approved', 422, 'Редактировать можно одобренные записи.');
            $data['tmdb_id'] = $existing->tmdb_id;
            $data['tmdb_type'] = $existing->tmdb_type;
        }
        $tmdbData = null;
        if (! empty($data['tmdb_id'])) {
            $tmdbData = $this->tmdb->details($data['tmdb_type'], $data['tmdb_id']);
            if (! $existing) {
                abort_if(Media::where('tmdb_id', $data['tmdb_id'])->where('tmdb_type', $data['tmdb_type'])->where('moderation_status', 'approved')->exists(), 409, 'Этот фильм уже есть в каталоге.');
                abort_if(ModerationRequest::where('tmdb_id', $data['tmdb_id'])->where('tmdb_type', $data['tmdb_type'])->where('status', 'pending')->exists(), 409, 'Заявка на этот фильм уже ожидает модерации.');
            }
        }
        $posterKey = $request->hasFile('poster') ? $request->file('poster')->store('posters', 'public')
            : ($tmdbData['poster_key'] ?? $existing?->poster_key);
        if (! array_key_exists('release_year', $data)) {
            $date = $tmdbData['release_date'] ?? $existing?->release_date?->format('Y-m-d');
            $data['release_year'] = $date ? substr($date, 0, 4) : null;
        }
        $item = DB::transaction(function () use ($request, $data, $tmdbData, $posterKey, $existing) {
            $item = ModerationRequest::create([
                'user_id' => $request->user()->id, 'title_ru' => $data['title_ru'], 'title_en' => $data['title_en'] ?? null,
                'type_id' => $data['type_id'], 'release_year' => $data['release_year'] ?? null,
                'description_ru' => $data['description_ru'] ?? null, 'poster_key' => $posterKey,
                'status' => 'pending', 'tmdb_data' => $tmdbData, 'tmdb_id' => $data['tmdb_id'] ?? null,
                'tmdb_type' => $data['tmdb_type'] ?? null, 'media_id' => $existing?->id, 'action' => $existing ? 'edit' : 'create',
                'genres_provided' => array_key_exists('genre_ids', $data) || ! empty($data['clear_genres']),
            ]);
            $item->genres()->sync(! empty($data['clear_genres']) ? [] : ($data['genre_ids'] ?? ($existing ? $existing->genres->pluck('id')->all() : [])));

            return $item;
        });

        return response()->json($item->load('genres', 'type'), 201);
    }

    public function approve(Request $request, ModerationRequest $moderationRequest)
    {
        abort_unless($request->user()->isModerator(), 403, 'Требуются права модератора.');
        $media = DB::transaction(function () use ($request, $moderationRequest) {
            $item = ModerationRequest::lockForUpdate()->findOrFail($moderationRequest->id);
            abort_unless($item->status === 'pending', 409, 'Эта заявка уже рассмотрена.');
            $media = $item->media_id ? Media::findOrFail($item->media_id) : null;
            if (! $media && $item->tmdb_id) {
                $media = Media::where('tmdb_id', $item->tmdb_id)->where('tmdb_type', $item->tmdb_type)->first();
                abort_if($media && $media->moderation_status === 'approved', 409, 'Этот фильм уже добавлен в каталог.');
            }
            if (! $media) {
                $media = Media::create(['title_ru' => $item->title_ru, 'type_id' => $item->type_id,
                    'tmdb_id' => $item->tmdb_id, 'tmdb_type' => $item->tmdb_type, 'moderation_status' => 'external']);
            }
            if ($item->tmdb_data) {
                $this->library->apply($media, $item->tmdb_data, true);
            }
            $releaseDate = $item->release_year ? ($item->tmdb_data['release_date'] ?? null) : null;
            if ($item->release_year && (! $releaseDate || substr($releaseDate, 0, 4) !== $item->release_year)) {
                $releaseDate = $item->release_year.'-01-01';
            }
            $media->update(['title_ru' => $item->title_ru, 'title_en' => $item->title_en,
                'type_id' => $item->type_id, 'description_ru' => $item->description_ru,
                'poster_key' => $item->poster_key,
                'release_date' => $releaseDate,
                'moderation_status' => 'approved']);
            if ($item->genres_provided || $item->genres()->exists()) {
                $media->genres()->sync($item->genres->modelKeys());
            }
            $item->update(['status' => 'approved', 'media_id' => $media->id,
                'moderator_id' => $request->user()->id, 'resolved_at' => now(), 'rejection_reason' => null]);

            return $media;
        });

        return response()->json(['message' => 'Заявка одобрена. Запись опубликована в каталоге.', 'media_id' => $media->id]);
    }

    public function reject(Request $request, ModerationRequest $moderationRequest)
    {
        abort_unless($request->user()->isModerator(), 403, 'Требуются права модератора.');
        $data = $request->validate(['reason' => 'required|string|min:1|max:1000']);
        DB::transaction(function () use ($request, $moderationRequest, $data) {
            $item = ModerationRequest::lockForUpdate()->findOrFail($moderationRequest->id);
            abort_unless($item->status === 'pending', 409, 'Эта заявка уже рассмотрена.');
            $item->update(['status' => 'rejected', 'rejection_reason' => $data['reason'],
                'moderator_id' => $request->user()->id, 'resolved_at' => now()]);
        });

        return response()->json(['message' => 'Заявка отклонена. Автор увидит причину.']);
    }
}
