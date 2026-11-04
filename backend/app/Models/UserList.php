<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class UserList extends Model
{
    protected $table = 'user_lists';

    protected $fillable = ['user_id', 'name', 'is_public', 'share_token'];

    protected function casts(): array
    {
        return ['is_public' => 'boolean'];
    }

    public function user() { return $this->belongsTo(User::class); }
    public function media() { return $this->belongsToMany(Media::class, 'list_media')->withPivot('added_at'); }
}