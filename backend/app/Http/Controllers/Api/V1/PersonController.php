<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\Person;
use Illuminate\Http\Request;

class PersonController extends Controller
{
    public function show($id)
    {
        $person = Person::with([
            'media' => function ($query) {
                $query->with(['type', 'genres'])
                      ->withPivot(['role_id', 'character'])
                      ->orderBy('release_date', 'desc');
            }
        ])->findOrFail($id);

        $filmography = $person->media->map(function ($media) {
            $role = \App\Models\Role::find($media->pivot->role_id);
            $roleName = $role ? $role->name_ru : 'Неизвестная роль';

            return [
                'id' => $media->id,
                'title_ru' => $media->title_ru,
                'title_en' => $media->title_en,
                'poster_url' => $media->poster_key ? 'storage/' . $media->poster_key : null,
                'release_date' => $media->release_date,
                'year' => $media->release_date ? \Carbon\Carbon::parse($media->release_date)->year : null,
                'type' => $media->type,
                'pivot' => [
                    'character' => $media->pivot->character ?? null,
                    'role_name_ru' => $roleName,
                ]
            ];
        });

        return response()->json([
            'id' => $person->id,
            'name' => $person->name,
            'photo_url' => $person->photo_key ? 'storage/' . $person->photo_key : null,
            'filmography' => $filmography,
        ]);
    }
}