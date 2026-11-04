<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\Entry;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ProfileController extends Controller
{
    public function show(Request $request)
    {
        $user = $request->user();

        $entries = Entry::where('user_id', $user->id)->with(['media', 'status'])->get();
        $totalEntries = $entries->count();
        $watchedCount = $entries->where('status.code', 'completed')->count();
        $avgRating = $entries->whereNotNull('rating')->avg('rating');
        $avgRating = $avgRating ? round($avgRating, 1) : 0;

        $topGenres = DB::table('entries')
            ->join('media', 'entries.media_id', '=', 'media.id')
            ->join('genre_media', 'media.id', '=', 'genre_media.media_id')
            ->join('genres', 'genre_media.genre_id', '=', 'genres.id')
            ->where('entries.user_id', $user->id)
            ->select('genres.name_ru', DB::raw('count(*) as count'))
            ->groupBy('genres.id', 'genres.name_ru')
            ->orderByDesc('count')
            ->limit(5)
            ->get();

        $recentActivity = Entry::where('user_id', $user->id)
            ->with(['media', 'status'])
            ->orderBy('created_at', 'desc')
            ->limit(5)
            ->get();

        return response()->json([
            'user' => [
                'name' => $user->name,
                'login' => $user->login,
                'email' => $user->email,
                'created_at' => $user->created_at,
            ],
            'stats' => [
                'total' => $totalEntries,
                'watched' => $watchedCount,
                'avg_rating' => $avgRating,
            ],
            'top_genres' => $topGenres,
            'recent_activity' => $recentActivity,
        ]);
    }

    public function update(Request $request)
    {
        $user = $request->user();

        $validated = $request->validate([
            'name' => 'required|string|max:100',
            'login' => [
                'required', 'string', 'max:32', 'regex:/^[a-zA-Z0-9_-]+$/',
                \Illuminate\Validation\Rule::unique('users')->ignore($user->id)
            ],
            'email' => [
                'required', 'email', 'max:255',
                \Illuminate\Validation\Rule::unique('users')->ignore($user->id)
            ],
            'current_password' => 'required_with:password|current_password',
            'password' => 'nullable|string|min:8|confirmed',
        ]);

        $user->name = $validated['name'];
        $user->login = $validated['login'];
        $user->email = $validated['email'];

        if (!empty($validated['password'])) {
            $user->password = \Illuminate\Support\Facades\Hash::make($validated['password']);
        }

        $user->save();

        return response()->json([
            'message' => 'Профиль успешно обновлен',
            'user' => [
                'name' => $user->name,
                'login' => $user->login,
                'email' => $user->email,
                'created_at' => $user->created_at,
            ]
        ]);
    }
}