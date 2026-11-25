<?php

namespace Database\Seeders;

use App\Models\Genre;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class DictionarySeeder extends Seeder
{
    public function run(): void
    {
        $types = [
            ['code' => 'movie',   'name_ru' => 'Фильмы',      'name_en' => 'Movies'],
            ['code' => 'series',  'name_ru' => 'Сериалы',     'name_en' => 'Series'],
            ['code' => 'anime',   'name_ru' => 'Аниме',       'name_en' => 'Anime'],
            ['code' => 'cartoon', 'name_ru' => 'Мультфильмы', 'name_en' => 'Cartoons'],
        ];

        $statuses = [
            ['code' => 'planned',   'name_ru' => 'Запланировано', 'name_en' => 'Planned'],
            ['code' => 'watching',  'name_ru' => 'Смотрю',       'name_en' => 'Watching'],
            ['code' => 'completed', 'name_ru' => 'Просмотрено',  'name_en' => 'Completed'],
            ['code' => 'dropped',   'name_ru' => 'Заброшено',    'name_en' => 'Dropped'],
            ['code' => 'paused',    'name_ru' => 'Отложено',     'name_en' => 'Paused'],
            ['code' => 'rewatched', 'name_ru' => 'Пересмотрено', 'name_en' => 'Rewatched'],
            ['code' => 'untracked', 'name_ru' => 'Без статуса',  'name_en' => 'No status'],
        ];

        $roles = [
            ['code' => 'director',   'name_ru' => 'Режиссёр',    'name_en' => 'Director'],
            ['code' => 'cast',       'name_ru' => 'В ролях',     'name_en' => 'Cast'],
            ['code' => 'writer',     'name_ru' => 'Сценарист',   'name_en' => 'Writer'],
            ['code' => 'production', 'name_ru' => 'Производство', 'name_en' => 'Production'],
            ['code' => 'composer',   'name_ru' => 'Композитор',  'name_en' => 'Composer'],
        ];

        foreach ($types as $row) {
            DB::table('media_types')->updateOrInsert(['code' => $row['code']], $row);
        }
        foreach ($statuses as $row) {
            DB::table('statuses')->updateOrInsert(['code' => $row['code']], $row);
        }
        foreach ($roles as $row) {
            DB::table('roles')->updateOrInsert(['code' => $row['code']], $row);
        }

        foreach (['Боевик', 'Приключения', 'Мультфильм', 'Комедия', 'Криминал', 'Документальный', 'Драма', 'Семейный', 'Фэнтези', 'История', 'Ужасы', 'Музыка', 'Детектив', 'Мелодрама', 'Фантастика', 'Триллер', 'Военный', 'Вестерн'] as $name) {
            Genre::firstOrCreate(['name_ru' => $name], ['name_en' => $name]);
        }
    }
}
