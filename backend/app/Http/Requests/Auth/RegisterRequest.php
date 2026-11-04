<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;

class RegisterRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'name'     => ['required', 'string', 'max:100'],
            'login'    => ['required', 'string', 'min:3', 'max:50', 'alpha_dash', 'unique:users,login'],
            'email'    => ['required', 'email', 'max:150', 'unique:users,email'],
            'password' => ['required', 'string', 'min:8', 'confirmed'],
            'language' => ['sometimes', 'in:ru,en'],
            'theme'    => ['sometimes', 'in:light,dark,system'],
        ];
    }
}