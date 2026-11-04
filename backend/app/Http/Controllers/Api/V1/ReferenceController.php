<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\MediaType;
use App\Models\Status;
use App\Models\Role;
use App\Models\Genre;
use Illuminate\Http\Request;

class ReferenceController extends Controller
{
    public function types()
    {
        return response()->json(MediaType::all());
    }

    public function statuses()
    {
        return response()->json(Status::all());
    }

    public function roles()
    {
        return response()->json(Role::all());
    }

    public function genres()
    {
        return response()->json(Genre::all());
    }
}