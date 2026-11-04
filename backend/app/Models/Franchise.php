<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Franchise extends Model
{
    protected $fillable = ['name', 'parent_id'];

    public function parent() { return $this->belongsTo(Franchise::class, 'parent_id'); }
    public function children() { return $this->hasMany(Franchise::class, 'parent_id'); }
    public function media() { return $this->hasMany(Media::class, 'franchise_id'); }
}