<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\UserList;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

class UserListController extends Controller
{
    public function index(Request $request)
    {
        return response()->json(UserList::where('user_id', $request->user()->id)->withCount('media')->latest()->get());
    }

    private function validated(Request $request, ?UserList $list = null): array
    {
        return $request->validate([
            'name' => ['required', 'string', 'max:255', Rule::unique('user_lists')->where('user_id', $request->user()->id)->ignore($list?->id)],
            'description' => 'nullable|string|max:5000', 'is_public' => 'required|boolean',
            'cover' => 'nullable|image|mimes:jpg,jpeg,png,webp|max:5120', 'remove_cover' => 'sometimes|boolean',
        ]);
    }

    public function store(Request $request)
    {
        $data = $this->validated($request);
        $list = UserList::create(['user_id' => $request->user()->id, 'name' => $data['name'], 'description' => $data['description'] ?? null,
            'is_public' => $data['is_public'], 'share_token' => $data['is_public'] ? Str::random(40) : null,
            'cover_key' => $request->hasFile('cover') ? $request->file('cover')->store('covers', 'public') : null]);

        return response()->json($list->loadCount('media'), 201);
    }

    public function show(Request $request, int $id)
    {
        return response()->json(UserList::where('user_id', $request->user()->id)->with('media.type', 'media.genres')->withCount('media')->findOrFail($id));
    }

    public function update(Request $request, int $id)
    {
        $list = UserList::where('user_id', $request->user()->id)->findOrFail($id);
        $data = $this->validated($request, $list);
        $fields = ['name' => $data['name'], 'description' => $data['description'] ?? null, 'is_public' => $data['is_public']];
        // Revoke the old public link when switching privacy, so it cannot be reused later.
        if (! $data['is_public']) {
            $fields['share_token'] = null;
        } elseif (! $list->share_token) {
            $fields['share_token'] = Str::random(40);
        }
        if ($request->hasFile('cover')) {
            $fields['cover_key'] = $request->file('cover')->store('covers', 'public');
        } elseif (! empty($data['remove_cover'])) {
            $fields['cover_key'] = null;
        }
        $list->update($fields);

        return response()->json($list->load('media.type')->loadCount('media'));
    }

    public function addMedia(Request $request, int $id)
    {
        $list = UserList::where('user_id', $request->user()->id)->findOrFail($id);
        $data = $request->validate(['media_id' => 'required|integer|exists:media,id']);
        $list->media()->syncWithoutDetaching([$data['media_id'] => ['added_at' => now()]]);

        return response()->json(['message' => 'Добавлено в коллекцию.']);
    }

    public function removeMedia(Request $request, int $id, int $mediaId)
    {
        $list = UserList::where('user_id', $request->user()->id)->findOrFail($id);
        $list->media()->detach($mediaId);

        return response()->json(['message' => 'Удалено из коллекции.']);
    }

    public function destroy(Request $request, int $id)
    {
        UserList::where('user_id', $request->user()->id)->findOrFail($id)->delete();

        return response()->json(['message' => 'Коллекция удалена.']);
    }
}
