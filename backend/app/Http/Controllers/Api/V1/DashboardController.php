<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\Entry;
use App\Models\Media;
use App\Models\User;
use App\Services\TmdbService;
use Illuminate\Http\Request;

class DashboardController extends Controller
{
    public function summary()
    {
        return response()->json(['catalog' => Media::where('moderation_status', 'approved')->count(), 'users' => User::count(), 'entries' => Entry::count()]);
    }

    public function recommendations(Request $request, TmdbService $tmdb)
    {
        $tracked = Entry::where('user_id', $request->user()->id)->with('media')->get()->pluck('media')->map(fn ($m) => $m->tmdb_type.':'.$m->tmdb_id)->all();
        $data = $tmdb->trending();
        $data['data'] = array_slice(array_values(array_filter($data['data'], fn ($m) => ! in_array($m['tmdb_type'].':'.$m['tmdb_id'], $tracked, true))), 0, 6);

        return response()->json($data);
    }
}
