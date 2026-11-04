<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class AddMediaToListRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'media_id' => 'required|exists:media,id',
        ];
    }
}