<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\Entry;
use App\Models\Episode;
use App\Models\EpisodeNote;
use App\Models\Media;
use App\Models\SeasonProgress;
use App\Services\TmdbService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class TrackingController extends Controller
{
    public function __construct(private TmdbService $tmdb) {}

    public function show(Request $request, Media $media)
    {
        $where = ['user_id' => $request->user()->id, 'media_id' => $media->id];

        return response()->json(['entry' => Entry::where($where)->with('status', 'episodeEntries.episode')->first(),
            'seasons' => SeasonProgress::where($where)->orderBy('season')->get(),
            'episode_notes' => EpisodeNote::where($where)->orderBy('season')->orderBy('episode')->get()]);
    }

    public function season(Media $media, int $season)
    {
        abort_if($season < 0 || $season > 1000, 404);
        if ($media->tmdb_type === 'tv') {
            $data = $this->tmdb->season($media->tmdb_id, $season);
            foreach ($data['episodes'] as &$episode) {
                $record = Episode::updateOrCreate(['media_id' => $media->id, 'season' => $season, 'number' => $episode['number']], ['title' => $episode['title']]);
                $episode['id'] = $record->id;
            }
            unset($episode);

            return response()->json($data);
        }

        return response()->json(['season' => $season, 'name' => 'Сезон '.$season, 'episodes' => $media->episodes()->where('season', $season)->get()]);
    }

    private function episodeCount(Media $media, int $season): int
    {
        abort_unless($media->tmdb_type === 'tv' || $media->type->code === 'series', 422, 'У фильма нет сезонов.');
        abort_if($season < 0 || $season > 1000, 404);
        $count = $media->tmdb_type === 'tv' ? count($this->tmdb->season($media->tmdb_id, $season)['episodes'])
            : $media->episodes()->where('season', $season)->count();
        abort_if($count === 0, 422, 'В этом сезоне пока нет серий.');

        return $count;
    }

    public function progress(Request $request, Media $media, int $season)
    {
        $data = $request->validate(['watched' => 'required|integer|min:0|max:10000', 'status' => 'sometimes|in:planned,watching,completed,dropped,paused,untracked']);
        $count = $this->episodeCount($media, $season);
        $watched = min($count, $data['watched']);
        $status = $data['status'] ?? ($watched === $count ? 'completed' : ($watched ? 'watching' : 'planned'));
        $progress = DB::transaction(function () use ($request, $media, $season, $watched, $status) {
            $where = ['user_id' => $request->user()->id, 'media_id' => $media->id];
            $progress = SeasonProgress::updateOrCreate($where + ['season' => $season], ['watched' => $watched, 'status' => $status]);
            Entry::where($where)->update(['episodes_watched' => SeasonProgress::where($where)->sum('watched'),
                'seasons_watched' => SeasonProgress::where($where)->where('status', 'completed')->count()]);

            return $progress;
        });

        return response()->json($progress);
    }

    public function note(Request $request, Media $media, int $season, int $episode)
    {
        $data = $request->validate(['note' => 'present|nullable|string|max:5000']);
        abort_if($episode < 1 || $episode > $this->episodeCount($media, $season), 422, 'Серия не существует.');
        $where = ['user_id' => $request->user()->id, 'media_id' => $media->id, 'season' => $season, 'episode' => $episode];
        if (trim($data['note'] ?? '') === '') {
            EpisodeNote::where($where)->delete();

            return response()->json(['deleted' => true]);
        }

        return response()->json(EpisodeNote::updateOrCreate($where, ['note' => $data['note']]));
    }
}
