<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreEntryRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'media_id'    => 'required|exists:media,id',
            'status_id'   => 'required|exists:statuses,id',
            'date'        => 'nullable|date',
            'rating'      => 'nullable|integer|min:1|max:10',
            'note'        => 'nullable|string|max:5000',
            'episodes'    => 'nullable|array',
            'episodes.*.episode_id' => 'required|exists:episodes,id',
            'episodes.*.watched'    => 'required|boolean',
            'episodes.*.rating'     => 'nullable|integer|min:1|max:10',
            'episodes.*.note'       => 'nullable|string|max:1000',
        ];
    }

    public function messages(): array
    {
        return [
            'rating.min' => 'Оценка должна быть от 1 до 10.',
            'rating.max' => 'Оценка должна быть от 1 до 10.',
        ];
    }
}