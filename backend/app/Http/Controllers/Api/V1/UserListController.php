<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\AddMediaToListRequest;
use App\Http\Requests\StoreUserListRequest;
use App\Models\UserList;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class UserListController extends Controller
{
    public function index(Request $request)
    {
        $lists = UserList::where('user_id', $request->user()->id)
            ->with('media')
            ->withCount('media')
            ->latest()
            ->get();

        return response()->json($lists);
    }

    public function store(StoreUserListRequest $request)
    {
        $data = $request->validated();
        $data['user_id'] = $request->user()->id;

        if (!empty($data['is_public'])) {
            $data['share_token'] = Str::random(32);
        }

        $list = UserList::create($data);

        return response()->json($list->load('media'), 201);
    }

    public function show(Request $request, $id)
    {
        $list = UserList::where('user_id', $request->user()->id)
            ->with('media')
            ->findOrFail($id);

        return response()->json($list);
    }

    public function addMedia(AddMediaToListRequest $request, $id)
    {
        $list = UserList::where('user_id', $request->user()->id)->findOrFail($id);
        $list->media()->attach($request->media_id, ['added_at' => now()]);

        return response()->json([
            'message' => 'Медиа успешно добавлено в список.',
            'data' => $list->load('media')
        ]);
    }

    public function removeMedia(Request $request, $id, $media_id)
    {
        $list = UserList::where('user_id', $request->user()->id)->findOrFail($id);

        $list->media()->detach($media_id);

        return response()->json([
            'message' => 'Медиа удалено из списка.',
            'data' => $list->load('media')
        ]);
    }
}