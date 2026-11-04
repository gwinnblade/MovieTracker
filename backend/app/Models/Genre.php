<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Genre extends Model
{
    protected $fillable = ['name_ru', 'name_en'];

    public function media() { return $this->belongsToMany(Media::class); }
}