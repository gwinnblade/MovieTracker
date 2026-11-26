<?php

return [
    'required' => 'Заполните поле «:attribute».',
    'required_with' => 'Заполните поле «:attribute».',
    'email' => 'Введите корректный email.',
    'unique' => 'Значение поля «:attribute» уже используется.',
    'confirmed' => 'Пароли не совпадают.',
    'current_password' => 'Текущий пароль указан неверно.',
    'alpha_dash' => 'Логин может содержать буквы, цифры, дефис и подчёркивание.',
    'integer' => 'Поле «:attribute» должно содержать целое число.',
    'string' => 'Поле «:attribute» должно содержать текст.',
    'boolean' => 'Недопустимое значение поля «:attribute».',
    'array' => 'Некорректный список в поле «:attribute».',
    'in' => 'Недопустимое значение поля «:attribute».',
    'exists' => 'Запись в поле «:attribute» не найдена.',
    'image' => 'Загрузите изображение JPEG, PNG или WebP.',
    'mimes' => 'Поддерживаются изображения JPEG, PNG и WebP.',
    'min' => ['numeric' => 'Значение поля «:attribute» должно быть не меньше :min.', 'string' => 'Поле «:attribute» должно содержать не меньше :min символов.'],
    'max' => ['numeric' => 'Значение поля «:attribute» должно быть не больше :max.', 'string' => 'Поле «:attribute» должно содержать не больше :max символов.', 'file' => 'Размер файла не должен превышать :max КБ.', 'array' => 'Слишком много элементов в поле «:attribute».'],
    'attributes' => ['name' => 'Имя', 'login' => 'Логин', 'email' => 'Email', 'password' => 'Пароль', 'current_password' => 'Текущий пароль',
        'title_ru' => 'Название', 'rating' => 'Оценка', 'note' => 'Заметка', 'reason' => 'Причина', 'watched' => 'Просмотрено', 'type_id' => 'Тип'],
];
