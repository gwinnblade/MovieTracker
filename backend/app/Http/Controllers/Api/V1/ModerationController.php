<?php

namespace App\Http\Controllers\Api\V1;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;
use App\Http\Controllers\Controller;
use App\Models\ModerationRequest;
use App\Models\Media;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ModerationController extends Controller
{
    private function checkModerator(Request $request)
    {
        if (!$request->user() || !$request->user()->isModerator()) {
            abort(403, 'Доступ запрещен. Требуются права модератора.');
        }
    }

    public function index(Request $request)
    {
        $this->checkModerator($request);
        
        $requests = ModerationRequest::with(['user', 'type'])
            ->orderBy('created_at', 'desc')
            ->get();
            
        return response()->json($requests);
    }

    public function store(Request $request)
    {
        $validated = $request->validate([
            'title_ru' => 'required|string|max:255',
            'title_en' => 'nullable|string|max:255',
            'type_id' => 'required|exists:media_types,id',
            'release_year' => 'nullable|string|size:4',
            'description_ru' => 'nullable|string',
            'poster' => 'nullable|file|mimes:jpeg,jpg,png,webp|max:5120',
            'genre_ids' => 'nullable|array',
            'genre_ids.*' => 'exists:genres,id',
            'tmdb_data' => 'nullable|string',
        ]);

        $posterKey = null;
        if ($request->hasFile('poster')) {
            $posterKey = $request->file('poster')->store('posters', 'public');
        }

        $requestItem = ModerationRequest::create([
            'user_id' => $request->user()->id,
            'title_ru' => $validated['title_ru'],
            'title_en' => $validated['title_en'] ?? null,
            'type_id' => $validated['type_id'],
            'release_year' => $validated['release_year'] ?? null,
            'description_ru' => $validated['description_ru'] ?? null,
            'poster_key' => $posterKey,
            'status' => 'pending',
            'tmdb_data' => $validated['tmdb_data'] ?? null,
        ]);

        if (!empty($validated['genre_ids'])) {
            $requestItem->genres()->attach($validated['genre_ids']);
        }

        return response()->json($requestItem->load('genres'), 201);
    }

    public function approve(Request $request, ModerationRequest $moderationRequest)
    {
        $this->checkModerator($request);

        DB::transaction(function () use ($moderationRequest) {
            $media = Media::create([
                'title_ru' => $moderationRequest->title_ru,
                'title_en' => $moderationRequest->title_en,
                'type_id' => $moderationRequest->type_id,
                'release_date' => $moderationRequest->release_year ? $moderationRequest->release_year . '-01-01' : null,
                'description_ru' => $moderationRequest->description_ru,
                'poster_key' => $moderationRequest->poster_key,
                'moderation_status' => 'approved',
            ]);

            if ($moderationRequest->genres->count() > 0) {
                $media->genres()->attach($moderationRequest->genres->pluck('id'));
            }

            if ($moderationRequest->tmdb_data) {
                $tmdbData = json_decode($moderationRequest->tmdb_data, true);

                $directorRole = \App\Models\Role::firstOrCreate(
                    ['code' => 'director'],
                    ['name_ru' => 'Режиссер', 'name_en' => 'Director']
                );
                $actorRole = \App\Models\Role::firstOrCreate(
                    ['code' => 'actor'],
                    ['name_ru' => 'Актер', 'name_en' => 'Actor']
                );

                $getOrCreatePerson = function ($personData) {
                    $person = \App\Models\Person::firstOrCreate(
                        ['name' => trim($personData['name'])]
                    );

                    if (!$person->photo_key && !empty($personData['profile_path'])) {
                        try {
                            $tmdbImageUrl = 'https://image.tmdb.org/t/p/w185' . $personData['profile_path'];
                            $response = Http::get($tmdbImageUrl);

                            if ($response->successful()) {
                                $fileName = 'person_' . $personData['tmdb_id'] . '.jpg';
                                $path = 'persons/' . $fileName;

                                Storage::disk('public')->put($path, $response->body());

                                $person->update(['photo_key' => $path]);
                            }
                        } catch (\Exception $e) {
                            \Log::error('Не удалось скачать фото персоны: ' . $e->getMessage());
                        }
                    }
                    
                    return $person;
                };

                $getOrCreateCompany = function ($name) {
                    return \App\Models\Company::firstOrCreate(['name' => trim($name)]);
                };

                if (!empty($tmdbData['director']['name'])) {
                    $person = $getOrCreatePerson($tmdbData['director']);
                    $media->persons()->attach($person->id, ['role_id' => $directorRole->id]);
                }

                if (!empty($tmdbData['cast']) && is_array($tmdbData['cast'])) {
                    foreach ($tmdbData['cast'] as $actor) {
                        if (!empty($actor['name'])) {
                            $person = $getOrCreatePerson($actor);
                            $media->persons()->attach($person->id, [
                                'role_id' => $actorRole->id,
                                'character' => $actor['character'] ?? null,
                            ]);
                        }
                    }
                }

                if (!empty($tmdbData['companies']) && is_array($tmdbData['companies'])) {
                    foreach ($tmdbData['companies'] as $company) {
                        if (!empty($company['name'])) {
                            $companyModel = $getOrCreateCompany($company['name']);
                            $media->companies()->attach($companyModel->id, [
                                'role_id' => $directorRole->id 
                            ]);
                        }
                    }
                }
            }

            $moderationRequest->update(['status' => 'approved']);
        });

        return response()->json(['message' => 'Заявка одобрена, фильм и связанные лица добавлены в каталог']);
    }

    public function reject(Request $request, ModerationRequest $moderationRequest)
    {
        $this->checkModerator($request);

        $validated = $request->validate([
            'reason' => 'required|string|max:500',
        ]);

        $moderationRequest->update([
            'status' => 'rejected',
            'rejection_reason' => $validated['reason'],
        ]);

        return response()->json(['message' => 'Заявка отклонена']);
    }
}