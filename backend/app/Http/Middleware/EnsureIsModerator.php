<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureIsModerator
{
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();
        
        if (!$user || !in_array($user->role, ['moderator', 'admin'], true)) {
            return response()->json(['message' => 'Доступ запрещен. Требуются права модератора или администратора.'], 403);
        }

        return $next($request);
    }
}