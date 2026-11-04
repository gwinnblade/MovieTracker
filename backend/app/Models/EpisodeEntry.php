<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class EpisodeEntry extends Model
{
    protected $table = 'episode_entries';

    protected $fillable = ['entry_id', 'episode_id', 'watched', 'rating', 'note'];

    protected function casts(): array
    {
        return ['watched' => 'boolean', 'rating' => 'integer'];
    }

    public function entry() { return $this->belongsTo(Entry::class, 'entry_id'); }
    public function episode() { return $this->belongsTo(Episode::class, 'episode_id'); }
}