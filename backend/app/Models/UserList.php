<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class UserList extends Model
{
    protected $table = 'user_lists';

    protected $fillable = ['user_id', 'name', 'description', 'cover_key', 'is_public', 'share_token'];

    protected $appends = ['cover_url'];

    public function getCoverUrlAttribute(): ?string
    {
        return $this->cover_key ? (str_starts_with($this->cover_key, 'http') ? $this->cover_key : '/storage/'.$this->cover_key) : null;
    }

    protected function casts(): array
    {
        return ['is_public' => 'boolean'];
    }

    public function user()
    {
        return $this->belongsTo(User::class);
    }

    public function media()
    {
        return $this->belongsToMany(Media::class, 'list_media')->withPivot('added_at');
    }
}
