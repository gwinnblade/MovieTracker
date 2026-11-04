<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Media extends Model
{
    protected $table = 'media';

    protected $appends = ['poster_url'];

    protected $fillable = [
        'type_id', 'franchise_id', 'title_ru', 'title_en', 'original_title',
        'description_ru', 'poster_key', 'release_date', 'moderation_status',
    ];

    protected function casts(): array
    {
        return ['release_date' => 'date'];
    }

    public function type(): BelongsTo
    {
        return $this->belongsTo(Type::class, 'type_id', 'id');
    }

    public function getPosterUrlAttribute(): ?string
    {
        if (!$this->poster_key) {
            return null;
        }

        if (str_starts_with($this->poster_key, 'http')) {
            return $this->poster_key;
        }

        $baseUrl = config('app.url') ?: 'http://localhost:8080';
        
        return $baseUrl . '/storage/' . $this->poster_key;
    }

    public function franchise() { return $this->belongsTo(Franchise::class, 'franchise_id'); }
    public function genres() { return $this->belongsToMany(Genre::class); }
    
    public function persons()
    {
        return $this->belongsToMany(Person::class, 'person_media')
            ->withPivot(['role_id', 'character']);
    }

    public function companies() 
    { 
        return $this->belongsToMany(Company::class, 'company_media')->withPivot('role_id');
    }
    public function episodes() { return $this->hasMany(Episode::class)->orderBy('season')->orderBy('number'); }
    public function entries() { return $this->hasMany(Entry::class); }
}