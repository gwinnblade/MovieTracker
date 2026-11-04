<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Type extends Model
{
    protected $table = 'media_types';

    protected $fillable = [
        'code',
        'name_ru',
        'name_en',
    ];

    public $timestamps = false;
}