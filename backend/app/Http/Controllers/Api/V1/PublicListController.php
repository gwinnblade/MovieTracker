<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\UserList;

class PublicListController extends Controller
{
    public function show($token)
    {
        $list = UserList::where('share_token', $token)
            ->where('is_public', true)
            ->with(['media' => function ($query) {
                $query->with(['type', 'genres']);
            }])
            ->first();


        if (!$list) {
            return response()->json(['message' => 'Список не найден или недоступен.'], 404);
        }

        return response()->json([
            'data' => [
                'id' => $list->id,
                'name' => $list->name,
                'is_public' => $list->is_public,
                'share_token' => $list->share_token,
                'media_count' => $list->media->count(),
                'media' => $list->media,
                'created_at' => $list->created_at,
                'updated_at' => $list->updated_at,
            ]
        ]);
    }
}