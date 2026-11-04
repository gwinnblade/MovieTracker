<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Person extends Model
{
    protected $table = 'persons';

    protected $fillable = ['name', 'photo_key'];

    public function media()
    {
        return $this->belongsToMany(Media::class, 'person_media')
                    ->withPivot(['role_id', 'character']);
    }

    public function roles()
    {
        return $this->belongsToMany(Role::class, 'person_media')
                    ->withPivot('media_id');
    }
}