<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class UpdateMediaRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'title_ru'         => 'sometimes|string|max:255',
            'title_en'         => 'nullable|string|max:255',
            'original_title'   => 'nullable|string|max:255',
            'description_ru'   => 'nullable|string',
            'type_id'          => 'sometimes|exists:media_types,id',
            'franchise_id'     => 'nullable|exists:franchises,id',
            'release_date'     => 'nullable|date',
            'genre_ids'        => 'sometimes|array',
            'genre_ids.*'      => 'exists:genres,id',
        ];
    }
}