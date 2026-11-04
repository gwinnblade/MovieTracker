<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Entry extends Model
{
    protected $table = 'entries';

    protected $fillable = ['user_id', 'media_id', 'status_id', 'date', 'rating', 'note'];

    protected function casts(): array
    {
        return ['date' => 'date', 'rating' => 'integer'];
    }

    public function user() { return $this->belongsTo(User::class); }
    public function media() { return $this->belongsTo(Media::class); }
    public function status() { return $this->belongsTo(Status::class, 'status_id'); }
    public function episodeEntries() { return $this->hasMany(EpisodeEntry::class, 'entry_id'); }
}