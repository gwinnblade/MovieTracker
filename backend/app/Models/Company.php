<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Company extends Model
{
    protected $fillable = ['name'];

    public function media() { return $this->belongsToMany(Media::class)->withPivot('role_id'); }
}