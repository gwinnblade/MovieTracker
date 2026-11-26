<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class EpisodeNote extends Model
{
    protected $guarded = ['id'];

    protected function casts(): array
    {
        return ['season' => 'integer', 'episode' => 'integer'];
    }
}
