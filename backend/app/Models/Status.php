<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Status extends Model
{
    protected $fillable = ['code', 'name_ru', 'name_en'];

    public function entries() { return $this->hasMany(Entry::class, 'status_id'); }
}