<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class User extends Authenticatable
{
    use HasFactory, Notifiable;

    protected $fillable = ['name', 'login', 'email', 'password', 'role', 'language', 'theme'];

    protected $hidden = ['password', 'remember_token'];

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    public function entries() { return $this->hasMany(Entry::class); }
    public function lists() { return $this->hasMany(UserList::class); }
    public function moderationRequests() { return $this->hasMany(ModerationRequest::class, 'author_id'); }
    public function moderatedRequests() { return $this->hasMany(ModerationRequest::class, 'moderator_id'); }

    public function isAdmin(): bool { return $this->role === 'admin'; }
    public function isModerator(): bool { return in_array($this->role, ['moderator', 'admin'], true); }
}