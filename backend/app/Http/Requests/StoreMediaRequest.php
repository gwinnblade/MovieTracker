<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreMediaRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'title_ru'         => 'required|string|max:255',
            'title_en'         => 'nullable|string|max:255',
            'original_title'   => 'nullable|string|max:255',
            'description_ru'   => 'nullable|string',
            'type_id'          => 'required|exists:media_types,id',
            'franchise_id'     => 'nullable|exists:franchises,id',
            'release_date'     => 'nullable|date',
            'genre_ids'        => 'required|array|min:1',
            'genre_ids.*'      => 'exists:genres,id',
            'companies'        => 'nullable|array',
            'persons'          => 'nullable|array',
        ];
    }

    public function messages(): array
    {
        return [
            'genre_ids.required' => 'Необходимо выбрать хотя бы один жанр.',
            'genre_ids.min'      => 'Необходимо выбрать хотя бы один жанр.',
        ];
    }
}