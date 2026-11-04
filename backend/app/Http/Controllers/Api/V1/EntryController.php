<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\StoreEntryRequest;
use App\Models\Entry;
use App\Models\EpisodeEntry;
use App\Models\Media;
use Illuminate\Http\Request;
use Mews\Purifier\Facades\Purifier;

class EntryController extends Controller
{
    // Получение списка отметок пользователя
    public function index(Request $request)
    {
        $user = $request->user();
        
        $query = Entry::with(['media', 'status', 'episodeEntries.episode'])
            ->where('user_id', $user->id);

        // Фильтр по статусу
        if ($request->filled('status_id')) {
            $query->where('status_id', $request->input('status_id'));
        }

        // Фильтр по типу медиа
        if ($request->filled('type_id')) {
            $query->whereHas('media', function ($q) use ($request) {
                $q->where('type_id', $request->input('type_id'));
            });
        }

        $entries = $query->latest()->paginate(15);

        return response()->json($entries);
    }

    // Получение конкретной отметки
    public function show(Request $request, $id)
    {
        $entry = Entry::with(['media', 'status', 'episodeEntries.episode'])
            ->where('user_id', $request->user()->id)
            ->findOrFail($id);

        return response()->json($entry);
    }

    // Создание или обновление отметки (upsert)
    public function store(StoreEntryRequest $request)
    {
        $user = $request->user();
        $validated = $request->validated();

        if (isset($validated['note'])) {
            $validated['note'] = Purifier::clean($validated['note'], 'default');
        }

        $entry = Entry::updateOrCreate(
            ['user_id' => $user->id, 'media_id' => $validated['media_id']],
            [
                'status_id' => $validated['status_id'],
                'date'      => $validated['date'] ?? null,
                'rating'    => $validated['rating'] ?? null,
                'note'      => $validated['note'] ?? null,
            ]
        );

        if (isset($validated['episodes'])) {
            $entry->episodeEntries()->delete();

            // Создаем новые
            foreach ($validated['episodes'] as $episodeData) {
                EpisodeEntry::create([
                    'entry_id'   => $entry->id,
                    'episode_id' => $episodeData['episode_id'],
                    'watched'    => $episodeData['watched'],
                    'rating'     => $episodeData['rating'] ?? null,
                    'note'       => isset($episodeData['note']) ? Purifier::clean($episodeData['note'], 'default') : null,
                ]);
            }
        }

        return response()->json([
            'message' => 'Отметка успешно сохранена.',
            'data'    => $entry->load(['media', 'status', 'episodeEntries.episode'])
        ], 201);
    }

    public function destroy(Request $request, $id)
    {
        $entry = Entry::where('user_id', $request->user()->id)->findOrFail($id);
        $entry->delete();

        return response()->json(['message' => 'Отметка удалена.']);
    }
}