<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class ModerationRequest extends Model
{
    protected $fillable = [
        'user_id',
        'title_ru',
        'title_en',
        'type_id',
        'release_year',
        'description_ru',
        'status',
        'rejection_reason',
        'poster_key',
        'tmdb_data',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function type(): BelongsTo
    {
        return $this->belongsTo(Type::class, 'type_id', 'id');
    }

    public function genres(): BelongsToMany
    {
        return $this->belongsToMany(Genre::class, 'genre_moderation_request');
    }

    protected function casts(): array
    {
        return ['payload' => 'array', 'resolved_at' => 'datetime'];
    }

    public function author() { return $this->belongsTo(User::class, 'author_id'); }
    public function media() { return $this->belongsTo(Media::class); }
    public function moderator() { return $this->belongsTo(User::class, 'moderator_id'); }
}