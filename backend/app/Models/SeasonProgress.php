<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class SeasonProgress extends Model
{
    protected $table = 'season_progress';

    protected $guarded = ['id'];

    protected function casts(): array
    {
        return ['season' => 'integer', 'watched' => 'integer'];
    }
}
