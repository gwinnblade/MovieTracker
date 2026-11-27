# База данных (database/)

Папка `database/` — «фундамент» приложения: здесь лежит сама SQLite-база,
миграции (схема таблиц), сиды (начальные данные) и фабрики (тестовые данные).

## Что в папке

| Путь | Что это |
|---|---|
| `database.sqlite` (+ `-shm`, `-wal`) | сам файл базы SQLite (WAL-режим) |
| `migrations/` | 27 файлов — схема всех таблиц |
| `seeders/` | начальные данные (справочники) |
| `factories/` | генератор тестовых пользователей |

---

## Миграции (migrations/)

Миграции описывают **схему** БД и применяются командой `php artisan migrate`.
Их 27, сгруппированы по доменам.

### Инфраструктура (Laravel)

| Миграция | Таблицы | Назначение |
|---|---|---|
| `0001_..._create_users_table` | `users`, `password_reset_tokens`, `sessions` | пользователи, сброс пароля, сессии |
| `0001_..._create_cache_table` | `cache` | хранилище кэша |
| `0001_..._create_jobs_table` | `jobs`, `job_batches`, `failed_jobs` | очереди задач |

### Справочники (каталог)

| Миграция | Таблица | Назначение |
|---|---|---|
| `..._create_media_types_table` | `media_types` | типы: movie / series / anime / cartoon |
| `..._create_statuses_table` | `statuses` | статусы дневника (planned, watching, ...) |
| `..._create_roles_table` | `roles` | роли персон (director, cast, writer, ...) |
| `..._create_genres_table` | `genres` | жанры |
| `..._create_companies_table` | `companies` | студии/компании |
| `..._create_persons_table` | `persons` | персоны (актёры, режиссёры) |
| `..._create_franchises_table` | `franchises` | франшизы (само-ссылка `parent_id`) |

### Каталог и связи

| Миграция | Таблица | Назначение |
|---|---|---|
| `..._create_media_table` | `media` | **ядро каталога** |
| `..._create_genre_media_table` | `genre_media` | pivot: жанр ↔ медиа |
| `..._create_company_media_table` | `company_media` | pivot: компания ↔ медиа (+ `role_id`) |
| `..._create_person_media_table` | `person_media` | pivot: персона ↔ медиа (+ `role_id`, `character`) |
| `..._create_episodes_table` | `episodes` | серии (уникал `media_id, season, number`) |

### Дневник и списки

| Миграция | Таблица | Назначение |
|---|---|---|
| `..._create_entries_table` | `entries` | **ядро дневника** (уникал `user_id, media_id`) |
| `..._create_episode_entries_table` | `episode_entries` | просмотр по сериям (уникал `entry_id, episode_id`) |
| `..._create_user_lists_table` | `user_lists` | пользовательские списки (+ `share_token`) |
| `..._create_list_media_table` | `list_media` | pivot: список ↔ медиа (+ `added_at`) |

### Модерация и поиск

| Миграция | Таблица | Назначение |
|---|---|---|
| `..._create_moderation_requests_table` | `moderation_requests` | заявки на добавление/изменение |
| `..._create_media_fts_table` | `media_fts` | **FTS5** полнотекстовый поиск по названиям |

### Поздние доработки (добавления к таблицам)

| Миграция | Что добавляет |
|---|---|
| `..._create_personal_access_tokens_table` | токены Sanctum |
| `..._add_poster_key_to_moderation_requests_table` | `poster_key` в заявки |
| `..._create_genre_moderation_request_table` | pivot: жанр ↔ заявка |
| `..._add_tmdb_data_to_moderation_requests_table` | `tmdb_data` (JSON) в заявку |
| `..._add_character_to_person_media_table` | `character` (имя персонажа) в pivot |

### «Порт Python-функций» и модерация жанров

| Миграция | Что делает |
|---|---|
| `2026_11_12_..._port_python_features` | **крупная**: TMDB-поля в `media`, прогресс в `entries`, новые таблицы `season_progress`, `episode_notes`, `legacy_posts`, `legacy_imports`; `avatar_key`, `legacy_id` в `users` |
| `2026_11_12_..._moderation_genre_selection` | `genres_provided` + частичный уникальный индекс «одна pending-заявка на TMDB» |

---

## Ключевые таблицы (схема)

### media — ядро каталога
```
id, type_id→media_types, franchise_id→franchises?,
title_ru, title_en?, original_title?, description_ru?,
poster_key?, release_date?, moderation_status (approved/pending/external),
tmdb_type?, tmdb_id?, tmdb_data? (JSON), tmdb_synced_at?, tmdb_failed_at?,
unique(tmdb_type, tmdb_id)
```

### entries — ядро дневника
```
id, user_id→users, media_id→media, status_id→statuses,
date?, rating? (0–10), note?,
progress, seasons_watched, episodes_watched,
legacy_id?, unique(user_id, media_id)
```

### person_media — pivot с ролью и персонажем
```
media_id, person_id, role_id, character?   (PK: media_id, person_id, role_id)
```

### season_progress / episode_notes — прогресс сериалов
```
season_progress: user_id, media_id, season, watched, status, unique(user,media,season)
episode_notes:   user_id, media_id, season, episode, note, unique(user,media,season,episode)
```

## FTS-поиск (media_fts) — особое

Таблица `media_fts` — виртуальная **FTS5** (полнотекстовый поиск SQLite):
```sql
CREATE VIRTUAL TABLE media_fts USING fts5(
    title_ru, title_en, original_title,
    content='media', content_rowid='id', tokenize='unicode61'
);
```
Три триггера (`AFTER INSERT/DELETE/UPDATE`) автоматически держат индекс в
актуальном состоянии. Именно на нём работает поиск по названию в
`MediaController` (префиксные запросы `"слово"*`).

---

## Сиды (seeders/)

| Сидер | Что делает |
|---|---|
| `DatabaseSeeder` | корневой: вызывает `DictionarySeeder` |
| `DictionarySeeder` | наполняет справочники: 4 типа, 7 статусов, 5 ролей, 18 жанров |

Запускается через `php artisan db:seed` (и автоматически из `app:bootstrap`).

## Фабрики (factories/)

| Фабрика | Что делает |
|---|---|
| `UserFactory` | генерирует тестовых пользователей (`login`, `email`, bcrypt-пароль) |

Используется в тестах (`php artisan test`) для быстрого создания данных.

---

## Как это работает вместе (для презентации)

```
php artisan migrate          → создаёт все таблицы (27 миграций)
php artisan db:seed          → DictionarySeeder (справочники)
   │
   ▼
database.sqlite (WAL)
   ├── users / sessions / cache / jobs      (инфраструктура)
   ├── media_types, statuses, roles, genres, companies, persons, franchises
   ├── media ── genre_media / company_media / person_media / episodes
   ├── entries ── episode_entries
   ├── user_lists ── list_media
   ├── season_progress / episode_notes      (прогресс сериалов)
   ├── moderation_requests                  (модерация)
   └── media_fts                            (FTS5-поиск)
```

**Результат:** вся схема БД описана декларативно в миграциях, начальные
данные — в сидах, а сам файл `database.sqlite` — результат их применения.
