<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class MediaType extends Model
{
    protected $fillable = ['code', 'name_ru', 'name_en'];

    public function media() { return $this->hasMany(Media::class, 'type_id'); }
}