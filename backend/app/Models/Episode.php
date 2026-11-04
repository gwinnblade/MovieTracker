<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Episode extends Model
{
    protected $fillable = ['media_id', 'season', 'number', 'title'];

    protected function casts(): array
    {
        return ['season' => 'integer', 'number' => 'integer'];
    }

    public function media() { return $this->belongsTo(Media::class); }
    public function episodeEntries() { return $this->hasMany(EpisodeEntry::class, 'episode_id'); }
}