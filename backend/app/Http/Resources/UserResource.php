<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class UserResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'login' => $this->login,
            'email' => $this->email,
            'role' => $this->role,
            'language' => $this->language,
            'theme' => $this->theme,
            'avatar_url' => $this->avatar_key ? (str_starts_with($this->avatar_key, 'http') ? $this->avatar_key : '/storage/'.$this->avatar_key) : null,
            'created_at' => $this->created_at,
        ];
    }
}
