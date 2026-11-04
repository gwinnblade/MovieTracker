<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\StoreMediaRequest;
use App\Http\Requests\UpdateMediaRequest;
use App\Models\Media;
use App\Models\ModerationRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;


class MediaController extends Controller
{
    public function index(Request $request)
    {
        $query = Media::with(['type', 'genres']);

        if ($request->filled('search')) {
            $search = $request->string('search')->trim();
            $query->where(function ($q) use ($search) {
                $q->where('title_ru', 'like', "%{$search}%")
                  ->orWhere('title_en', 'like', "%{$search}%")
                  ->orWhere('original_title', 'like', "%{$search}%");
            });
        }

        if ($request->filled('type_id')) {
            $query->where('type_id', $request->type_id);
        }

        if ($request->filled('year_from')) {
            $query->whereYear('release_date', '>=', $request->year_from);
        }
        if ($request->filled('year_to')) {
            $query->whereYear('release_date', '<=', $request->year_to);
        }

        if ($request->filled('genre_ids')) {
            $genreIds = explode(',', $request->string('genre_ids')); 

            foreach ($genreIds as $genreId) {
                $query->whereHas('genres', function ($q) use ($genreId) {
                    $q->where('genres.id', $genreId);
                });
            }
        }

        $sortBy = $request->get('sort_by', 'release_date'); 
        $sortOrder = $request->get('sort_order', 'desc');

        $allowedSorts = ['release_date', 'title_ru', 'avg_rating'];
        if (in_array($sortBy, $allowedSorts)) {
            $query->orderBy($sortBy, $sortOrder);
        }

        // Пагинация
        $limit = $request->get('limit', 12);
        $media = $query->paginate($limit);

        return response()->json($media);
    }

    public function store(StoreMediaRequest $request)
    {
        $user = $request->user();

        $payload = $request->validated();

        $moderationRequest = ModerationRequest::create([
            'author_id' => $user->id,
            'media_id'  => null,
            'type'      => 'create',
            'payload'   => $payload,
            'status'    => 'pending',
        ]);

        return response()->json([
            'message' => 'Заявка на создание медиа успешно отправлена на модерацию.',
            'data'    => [
                'request_id' => $moderationRequest->id,
                'status'     => $moderationRequest->status,
            ]
        ], 202); // 202 Accepted
    }

    public function update(UpdateMediaRequest $request, $id)
    {
        $media = Media::findOrFail($id);
        $user = $request->user();

        $payload = $request->validated();

        $modRequest = ModerationRequest::create([
            'author_id' => $user->id,
            'media_id'  => $media->id, 
            'type'      => 'edit',
            'payload'   => $payload,
            'status'    => 'pending',
        ]);

        return response()->json([
            'message' => 'Заявка на редактирование медиа успешно отправлена на модерацию.',
            'data'    => [
                'request_id' => $modRequest->id,
                'status'     => $modRequest->status,
            ]
        ], 202); 
    }

    public function random()
    {
        $media = Media::with(['type', 'franchise', 'genres', 'companies', 'persons', 'episodes'])
            ->where('moderation_status', 'approved')
            ->inRandomOrder()
            ->first();

        if (!$media) {
            return response()->json(['message' => 'В каталоге пока нет одобренного медиа.'], 404);
        }

        return response()->json($media);
    }

    public function similar($id)
    {
        $media = Media::with(['persons' => function ($query) {
            $query->whereHas('roles', function ($q) {
                $q->where('code', 'director');
            });
        }])->findOrFail($id);

        $director = $media->persons->first();

        if (!$director) {
            return response()->json([
                'director' => null,
                'movies' => []
            ]);
        }

        $similarMovies = Media::whereHas('persons', function ($query) use ($director) {
            $query->where('person_id', $director->id)
                  ->whereHas('roles', function ($q) {
                      $q->where('code', 'director');
                  });
        })
        ->where('id', '!=', $id)
        ->with('type')
        ->orderBy('release_date', 'desc')
        ->limit(6)
        ->get(['id', 'title_ru', 'title_en', 'poster_key', 'release_date', 'type_id']);

        $movies = $similarMovies->map(function ($movie) {
            return [
                'id' => $movie->id,
                'title_ru' => $movie->title_ru,
                'title_en' => $movie->title_en,
                'poster_url' => $movie->poster_key ? 'storage/' . $movie->poster_key : null,
                'release_date' => $movie->release_date,
                'year' => $movie->release_date ? \Carbon\Carbon::parse($movie->release_date)->year : null,
                'type' => $movie->type,
            ];
        });

        return response()->json([
            'director' => [
                'id' => $director->id,
                'name' => $director->name,
            ],
            'movies' => $movies,
        ]);
    }

    public function show($id)
    {
        $media = Media::with([
            'type',
            'genres',
            'persons' => function ($query) {
                $query->withPivot(['role_id', 'character'])->with('roles');
            },
            'companies' => function ($query) {
                $query->withPivot('role_id');
            }
        ])->findOrFail($id);

        // Форматируем персон, отдавая ОТНОСИТЕЛЬНЫЙ путь
        $formattedPersons = $media->persons->map(function ($person) {
            return [
                'id' => $person->id,
                'name' => $person->name,
                // Отдаем просто 'storage/...', без asset()!
                'photo_url' => $person->photo_key ? 'storage/' . $person->photo_key : null,
                'roles' => $person->roles->map(function ($role) {
                    return [
                        'id' => $role->id,
                        'code' => $role->code,
                        'name_ru' => $role->name_ru,
                        'name_en' => $role->name_en,
                    ];
                }),
                'pivot' => [
                    'character' => $person->pivot->character ?? null,
                    'role_id' => $person->pivot->role_id ?? null,
                ]
            ];
        })->toArray();

        $response = [
            'id' => $media->id,
            'type_id' => $media->type_id,
            'franchise_id' => $media->franchise_id,
            'title_ru' => $media->title_ru,
            'title_en' => $media->title_en,
            'original_title' => $media->original_title,
            'description_ru' => $media->description_ru,
            'poster_key' => $media->poster_key,
            'poster_url' => $media->poster_key ? 'storage/' . $media->poster_key : null,
            'release_date' => $media->release_date,
            'moderation_status' => $media->moderation_status,
            'created_at' => $media->created_at,
            'updated_at' => $media->updated_at,
            'persons' => $formattedPersons,
            'type' => $media->type,
            'genres' => $media->genres,
            'companies' => $media->companies->map(function ($company) {
                return [
                    'id' => $company->id,
                    'name' => $company->name,
                    'pivot' => [
                        'role_id' => $company->pivot->role_id ?? null,
                    ]
                ];
            })->toArray(),
        ];

        return response()->json($response);
    }
}