# Маршруты (routes/)

Папка `routes/` — «входная дверь» приложения: здесь описано, какой URL
отдаёт какой контроллер. В проекте три файла:

| Файл | Назначение |
|---|---|
| `api.php` | **основной** — весь REST API (префикс `/api/v1`) |
| `web.php` | веб-страница (только `welcome`) |
| `console.php` | artisan-команда `inspire` |

Весь функционал приложения живёт в `api.php`. Ниже — его разбор.

---

## api.php — REST API

Все маршруты внутри `Route::prefix('v1')`, поэтому полный URL имеет вид
`/api/v1/...`. Маршруты разбиты на **3 группы по middleware** — это и есть
уровни доступа:

```
/api/v1
 ├── ПУБЛИЧНОЕ        (throttle:180,1)          — без входа
 ├── AUTH            (throttle:10,1)           — вход/регистрация
 └── ЗАЩИЩЁННОЕ      (auth:sanctum + throttle) — только вошедший
```

### 1. Публичное чтение (без входа)

Middleware: `throttle:180,1` (лимит 180 запросов/мин).

| Метод | Маршрут | Контроллер |
|---|---|---|
| GET | `summary` | `DashboardController@summary` |
| GET | `tmdb/trending` | `TmdbController@trending` |
| GET | `tmdb/search` | `TmdbController@search` |
| GET | `tmdb/details` | `TmdbController@details` |
| GET | `tmdb/tv/{id}/season/{season}` | `TmdbController@season` |
| GET | `persons/{id}` | `PersonController@show` |
| GET | `reference/{types,statuses,roles,genres}` | `ReferenceController` (цикл) |
| GET | `media/random` | `MediaController@random` |
| GET | `media` | `MediaController@index` |
| GET | `media/{id}` | `MediaController@show` |
| GET | `media/{id}/similar` | `MediaController@similar` |
| GET | `media/{media}/seasons/{season}` | `TrackingController@season` |
| GET | `public/lists/{token}` | `PublicListController@show` |
| GET | `public/collections/{id}` | `PublicListController@byId` |

> Справочники (`types`, `statuses`, `roles`, `genres`) регистрируются **циклом**
> — один маршрут на каждое значение.

### 2. Аутентификация (без входа, но с жёстким лимитом)

Middleware: `throttle:10,1` (лимит 10/мин — защита от брутфорса).

| Метод | Маршрут | Контроллер |
|---|---|---|
| POST | `auth/register` | `AuthController@register` |
| POST | `auth/login` | `AuthController@login` |
| POST | `auth/forgot-password` | `AuthController@forgotPassword` |
| POST | `auth/reset-password` | `AuthController@resetPassword` |

### 3. Защищённое (только вошедший)

Middleware: `auth:sanctum` + `throttle:180,1`.

**Профиль и сессия**

| Метод | Маршрут | Контроллер |
|---|---|---|
| GET | `auth/me` | `AuthController@me` |
| POST | `auth/logout` | `AuthController@logout` |
| GET/PUT/POST | `profile` | `ProfileController@show/update` |

**Дневник (ядро)**

| Метод | Маршрут | Контроллер |
|---|---|---|
| GET | `entries` | `EntryController@index` |
| GET | `entries/{id}` | `EntryController@show` |
| POST | `entries` | `EntryController@store` |
| DELETE | `entries/{id}` | `EntryController@destroy` |

**Трекинг сериалов**

| Метод | Маршрут | Контроллер |
|---|---|---|
| GET | `media/{media}/tracking` | `TrackingController@show` |
| PUT | `media/{media}/seasons/{season}/progress` | `TrackingController@progress` |
| PUT | `media/{media}/seasons/{season}/episodes/{episode}/note` | `TrackingController@note` |

**Списки**

| Метод | Маршрут | Контроллер |
|---|---|---|
| GET | `lists` | `UserListController@index` |
| POST | `lists` | `UserListController@store` |
| GET | `lists/{id}` | `UserListController@show` |
| PUT/POST | `lists/{id}` | `UserListController@update` |
| DELETE | `lists/{id}` | `UserListController@destroy` |
| POST | `lists/{id}/media` | `UserListController@addMedia` |
| DELETE | `lists/{id}/media/{mediaId}` | `UserListController@removeMedia` |

**Модерация**

| Метод | Маршрут | Контроллер | Примечание |
|---|---|---|---|
| GET | `moderation/requests` | `ModerationController@index` | свои — всем, чужие — модератору |
| POST | `moderation/requests` | `ModerationController@store` | доп. `throttle:15,1` |
| POST | `moderation/requests/{id}/approve` | `ModerationController@approve` | проверка в контроллере |
| POST | `moderation/requests/{id}/reject` | `ModerationController@reject` | проверка в контроллере |
| POST | `media` | `ModerationController@store` | заявка на добавление |

> **Важно:** права модератора для `approve`/`reject` проверяются **внутри
> контроллера** (`abort_unless($request->user()->isModerator(), 403)`), а не
> middleware маршрута. Middleware `EnsureIsModerator` (алиас `moderator`)
> зарегистрирован в `bootstrap/app.php`, но в маршрутах не используется.

---

## web.php — веб

Один маршрут: `GET /` → `view('welcome')`. Бэкенд отдаёт только заглушку;
весь UI живёт во фронтенде (Next.js), а не здесь.

## console.php — консоль

Одна команда: `php artisan inspire` — печатает случайную цитату.
Стандартная, из шаблона Laravel.

---

## Как это работает вместе (для презентации)

```
HTTP-запрос
   │
   ▼
routes/api.php  ──►  префикс /api/v1
   │
   ├── ПУБЛИЧНОЕ      throttle:180,1        → чтение каталога/справочников
   ├── AUTH           throttle:10,1         → login/register/reset
   └── ЗАЩИЩЁННОЕ     auth:sanctum+throttle → дневник, списки, трекинг, модерация
   │
   ▼
Controller (Api/V1/*)  ──►  Model / Service  ──►  БД
```

**Результат:** доступ к API разделён на три уровня (публичное чтение →
вход → защищённые действия), а лимиты `throttle` защищают от злоупотребления.
