<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\RegisterRequest;
use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function register(RegisterRequest $request)
    {
        $user = User::create($request->validated());

        return response()->json(new UserResource($user), 201);
    }

    public function login(LoginRequest $request)
    {
        $login = $request->input('login');
        $field = filter_var($login, FILTER_VALIDATE_EMAIL) ? 'email' : 'login';

        if (! Auth::attempt([$field => $login, 'password' => $request->input('password')], $request->boolean('remember'))) {
            throw ValidationException::withMessages([
                'login' => __('auth.failed'),
            ]);
        }

        $request->session()->regenerate();

        return response()->json(new UserResource($request->user()));
    }

    public function logout(Request $request)
    {
        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return response()->json(['message' => 'ok']);
    }

    public function me(Request $request)
    {
        return response()->json(new UserResource($request->user()));
    }
}