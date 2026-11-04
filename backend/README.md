# MovieTracker Backend API

RESTful API для веб-приложения MovieTracker, обеспечивающее управление каталогом фильмов, пользовательскими списками, системой модерации и интеграцию с внешним API (TMDB).

![Laravel](https://img.shields.io/badge/Laravel-13-FF2D20?logo=laravel)
![PHP](https://img.shields.io/badge/PHP-8.2+-777BB4?logo=php)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?logo=sqlite)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)

---

## Структура проекта

```text
backend/
├── app/
│   ├── Http/
│   │   ├── Controllers/
│   │   │   ├── Api/           # Контроллеры API (Media, Auth, Entries, Lists, Moderation)
│   │   │   └── Auth/          # Контроллеры аутентификации (Sanctum)
│   │   ├── Middleware/        # Кастомные middleware (например, проверка ролей)
│   │   └── Requests/          # Form Request классы для валидации входящих данных
│   ├── Models/                # Eloquent модели (User, Media, Entry, UserList, ModerationRequest)
│   ├── Services/              # Бизнес-логика
│   │   └── TmdbService.php    # Сервис для взаимодействия с TMDB API v4
│   └── Providers/             # Service Providers
├── config/                    # Конфигурационные файлы (включая services.php для TMDB)
├── database/
│   ├── migrations/            # Миграции БД (включая FTS5 для полнотекстового поиска)
│   ├── seeders/               # Сидеры для справочников (жанры, статусы, типы)
│   └── database.sqlite        # Файл базы данных (игнорируется в Git)
├── routes/
│   ├── api.php                # Маршруты API (v1)
│   └── web.php                # Маршруты для Sanctum CSRF cookie
├── storage/                   # Логи, кэш, временные файлы
├── tests/                     # PHPUnit / Pest тесты
├── .env.example               # Шаблон переменных окружения
├── composer.json              # Зависимости PHP
└── Dockerfile                 # Конфигурация для контейнеризации (PHP-FPM + Nginx)
```

---

## Локальная разработка

### Требования

- PHP 8.2 или выше
- Composer
- SQLite3 (или другая поддерживаемая СУБД)

### Установка

1. Установите зависимости:

   ```bash
   composer install
   ```

2. Создайте файл окружения:

   ```bash
   cp .env.example .env
   ```

3. Сгенерируйте ключ приложения:

   ```bash
   php artisan key:generate
   ```

4. **Важно:** Откройте `.env` и добавьте ваш ключ TMDB:

   ```env
   TMDB_API_KEY="ваш_длинный_jwt_токен_v4"
   DB_CONNECTION=sqlite
   DB_DATABASE=database/database.sqlite
   ```

5. Создайте файл БД и выполните миграции с сидерами:

   ```bash
   touch database/database.sqlite
   php artisan migrate --seed
   ```

6. (Опционально) Создайте администратора через Tinker:

   ```bash
   php artisan tinker
   ```

   ```php
   App\Models\User::create([
       'login'    => 'admin',
       'email'    => 'admin@movietracker.local',
       'password' => Hash::make('SuperAdmin2026!'),
       'role'     => 'admin',
   ]);
   exit
   ```

7. Запустите локальный сервер:

   ```bash
   php artisan serve --port=8080
   ```

---

## API Документация

- **Base URL:** `http://localhost:8080/api` (или `http://localhost:8080/api/v1` в зависимости от префикса в `api.php`)
- **Формат ответов:** `application/json`

### Аутентификация (Laravel Sanctum)

Для SPA-аутентификации (фронтенд на том же домене или через прокси):

1. Сделайте `GET` запрос на `/sanctum/csrf-cookie` для получения куки `XSRF-TOKEN`.
2. При последующих запросах отправляйте:

   ```http
   Accept: application/json
   X-XSRF-TOKEN: <значение_из_cookie>
   Origin: http://localhost:3000
   ```

### 1. Аутентификация и Пользователь

| Метод | Путь             | Описание                                              | Доступ   |
| ----- | ---------------- | ----------------------------------------------------- | -------- |
| POST  | `/auth/register` | Регистрация нового пользователя                       | Публичный |
| POST  | `/auth/login`    | Вход в систему                                        | Публичный |
| POST  | `/auth/logout`   | Выход из системы (аннулирование сессии)               | Auth     |
| GET   | `/auth/me`       | Получение данных текущего пользователя (включая role) | Auth     |

### 2. Справочники (Reference)

| Метод | Путь                  | Описание                                            | Доступ    |
| ----- | --------------------- | --------------------------------------------------- | --------- |
| GET   | `/reference/types`    | Список типов медиа (Фильмы, Сериалы, Аниме)         | Публичный |
| GET   | `/reference/statuses` | Статусы просмотра (Смотрю, Просмотрено, Брошено)    | Публичный |
| GET   | `/reference/genres`   | Список жанров                                       | Публичный |

### 3. Каталог Медиа

| Метод | Путь             | Описание                                                       | Доступ    |
| ----- | ---------------- | -------------------------------------------------------------- | --------- |
| GET   | `/media`         | Поиск и фильтрация медиа (пагинация)                           | Публичный |
| GET   | `/media/random`  | Случайное одобренное медиа                                     | Публичный |
| GET   | `/media/{id}`    | Детальная информация о медиа (включая cast, crew, companies)   | Публичный |
| POST  | `/media`         | Создание заявки на добавление нового медиа                     | Auth      |
| PUT   | `/media/{id}`    | Создание заявки на редактирование существующего медиа          | Auth      |

**Параметры для `GET /media`:**

- `search` (string): Полнотекстовый поиск (поддерживает префиксы, например, `матриц` → `матриц*`)
- `type_id` (int): Фильтр по типу медиа
- `genre_id` (int): Фильтр по жанру
- `sort_by` (string): `created_at`, `release_date`, `title_ru` (по умолч. `created_at`)
- `sort_direction` (string): `asc` или `desc` (по умолч. `desc`)
- `per_page` (int): Элементов на страницу (по умолч. `15`)

### 4. Пользовательские отметки (Entries)

| Метод  | Путь            | Описание                              | Доступ |
| ------ | --------------- | ------------------------------------- | ------ |
| GET    | `/entries`      | Список отметок пользователя           | Auth   |
| POST   | `/entries`      | Создание или обновление отметки (Upsert) | Auth   |
| DELETE | `/entries/{id}` | Удаление отметки                      | Auth   |

**Тело запроса для `POST /entries`:**

```json
{
  "media_id": 603,
  "status_id": 2,
  "rating": 9,
  "date": "2026-11-03",
  "note": "<p>Отличный фильм!</p>",
  "episodes": [
    { "episode_id": 1, "watched": true, "rating": 8, "note": "Хороший пилот" }
  ]
}
```

### 5. Пользовательские списки (User Lists)

| Метод  | Путь                          | Описание                    | Доступ |
| ------ | ----------------------------- | --------------------------- | ------ |
| GET    | `/lists`                      | Все списки текущего пользователя | Auth |
| POST   | `/lists`                      | Создание нового списка      | Auth   |
| POST   | `/lists/{id}/media`           | Добавление медиа в список   | Auth   |
| DELETE | `/lists/{id}/media/{media_id}` | Удаление медиа из списка    | Auth   |

> Если при создании списка указать `"is_public": true`, сервер автоматически сгенерирует 32-символьный `share_token`.

### 6. Модерация (Moderation)

| Метод | Путь                                | Описание                                                               | Доступ              |
| ----- | ----------------------------------- | ---------------------------------------------------------------------- | ------------------- |
| GET   | `/moderation/requests`              | Очередь заявок (status: pending)                                       | Moderator / Admin   |
| POST  | `/moderation/requests/{id}/approve` | Одобрение заявки (создание/обновление медиа + загрузка данных из TMDB) | Moderator / Admin   |
| POST  | `/moderation/requests/{id}/reject`  | Отклонение заявки с комментарием                                       | Moderator / Admin   |

---

## Технические особенности реализации

- **Интеграция с TMDB API v4:** Используется `Illuminate\Support\Facades\Http` с Bearer-токеном (`withToken`) для аутентификации. Реализована корректная сборка полных URL для постеров и фото актёров (`image.tmdb.org/t/p/w500`).
- **Полнотекстовый поиск (FTS5):** Виртуальная таблица `media_fts` с триггерами SQLite обеспечивает мгновенный и релевантный поиск по названиям на русском и английском языках.
- **Безопасность (XSS Protection):** Все пользовательские текстовые данные (заметки, комментарии) проходят санитизацию через пакет `mews/purifier` перед сохранением в БД.
- **Архитектура модерации:** Прямое редактирование одобренного контента обычными пользователями запрещено. Любые изменения создают запись в `moderation_requests` с типом `edit`, которая требует одобрения модератора.
- **Контейнеризация:** Проект полностью готов к запуску через Docker Compose (PHP 8.4-FPM + Nginx + Supervisor), включая автоматическое выполнение миграций при первом старте.