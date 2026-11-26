<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Resources\UserResource;
use App\Models\Entry;
use App\Models\SeasonProgress;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;

class ProfileController extends Controller
{
    public function show(Request $request)
    {
        $user = $request->user();
        $entries = Entry::where('user_id', $user->id)->with('media.type', 'status')->get();
        $rated = $entries->whereNotNull('rating');
        $topGenres = DB::table('entries')->join('genre_media', 'entries.media_id', '=', 'genre_media.media_id')
            ->join('genres', 'genre_media.genre_id', '=', 'genres.id')->where('entries.user_id', $user->id)
            ->select('genres.name_ru', DB::raw('count(*) as count'))->groupBy('genres.id', 'genres.name_ru')->orderByDesc('count')->limit(6)->get();

        return response()->json(['user' => new UserResource($user), 'stats' => [
            'total' => $entries->count(), 'watched' => $entries->whereIn('status.code', ['completed', 'rewatched'])->count(),
            'movies' => $entries->where('media.tmdb_type', 'movie')->count() + $entries->whereNull('media.tmdb_type')->where('media.type.code', 'movie')->count(),
            'series' => $entries->where('media.tmdb_type', 'tv')->count() + $entries->whereNull('media.tmdb_type')->where('media.type.code', 'series')->count(),
            'rated' => $rated->count(), 'avg_rating' => round($rated->avg('rating') ?? 0, 1),
            'episodes_watched' => (int) SeasonProgress::where('user_id', $user->id)->sum('watched'),
            'collections' => $user->lists()->count(),
            'statuses' => $entries->groupBy('status.code')->map(fn ($items) => ['name' => $items->first()->status->name_ru, 'count' => $items->count()])->values(),
        ], 'top_genres' => $topGenres,
            'recent_activity' => $entries->sortByDesc('id')->take(6)->values(),
            'continue_watching' => $entries->where('status.code', 'watching')->sortByDesc('updated_at')->take(6)->values(),
            'top_rated' => $rated->sortByDesc('rating')->take(6)->values()]);
    }

    public function update(Request $request)
    {
        $user = $request->user();
        $data = $request->validate([
            'name' => 'required|string|max:100', 'login' => ['required', 'string', 'min:3', 'max:50',
                Rule::when($request->input('login') !== $user->login, 'alpha_dash'), Rule::unique('users')->ignore($user->id)],
            'email' => ['required', 'email', 'max:255', Rule::unique('users')->ignore($user->id)],
            'current_password' => 'required_with:password|current_password', 'password' => 'nullable|string|min:8|confirmed',
            'avatar' => 'nullable|image|mimes:jpeg,jpg,png,webp|max:5120', 'remove_avatar' => 'sometimes|boolean',
        ]);
        $fields = array_intersect_key($data, array_flip(['name', 'login', 'email']));
        if (! empty($data['password'])) {
            $fields['password'] = $data['password'];
        }
        if ($request->hasFile('avatar')) {
            $fields['avatar_key'] = $request->file('avatar')->store('avatars', 'public');
        } elseif (! empty($data['remove_avatar'])) {
            $fields['avatar_key'] = null;
        }
        $user->update($fields);

        return response()->json(['message' => 'Профиль сохранён.', 'user' => new UserResource($user)]);
    }
}
