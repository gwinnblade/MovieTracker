# Конфигурация (config/)

Папка `config/` — «центр настроек» Laravel. Каждый файл отвечает за одну
подсистему; значения берутся из переменных окружения `.env`, поэтому один и
тот же код работает в локальном Docker, на тесте и в проде без правки кода.

Ниже — все 14 файлов. Отмечены **изменённые под проект** (не стандартный
Laravel) — именно их стоит показать на презентации.

## Краткая таблица

| Файл | Что настраивает | Изменён под проект? |
|---|---|---|
| `app.php` | имя, env, debug, URL, ключ шифрования | ✅ добавлен `frontend_url` |
| `auth.php` | guard, провайдер пользователей, сброс пароля | ✅ драйвер `legacy-eloquent` |
| `cache.php` | хранилища кэша | по умолчанию `database` |
| `cors.php` | кросс-доменные запросы (CORS) | ✅ разрешены порты 3000–3002 |
| `database.php` | подключения к БД | по умолчанию `sqlite` |
| `filesystems.php` | диски хранения файлов | стандартный |
| `legacy.php` | параметры импорта старой БД | ✅ **свой файл** |
| `logging.php` | каналы логов (Monolog) | стандартный |
| `mail.php` | почтовые транспорты | по умолчанию `log` |
| `purifier.php` | настройки HTMLPurifier | стандартный (пакет) |
| `queue.php` | очереди задач | по умолчанию `database` |
| `sanctum.php` | stateful-аутентификация SPA | стандартный |
| `services.php` | ключи сторонних сервисов | ✅ добавлен `tmdb` |
| `session.php` | драйвер и cookie сессий | по умолчанию `database` |

---

## app.php — приложение

Базовые параметры: имя, окружение (`APP_ENV`), debug, часовой пояс, locale.
**Своё:** поле `frontend_url` (env `FRONTEND_URL`, по умолчанию
`http://localhost:3002`) — адрес фронтенда-SPA. Используется в
`AppServiceProvider` для ссылки сброса пароля и в других местах, где нужно
сгенерировать URL фронтенда из бэкенда.

## auth.php — аутентификация

**Самое важное для проекта:** провайдер пользователей использует драйвер
`legacy-eloquent`:

```php
'providers' => [
    'users' => [
        'driver' => 'legacy-eloquent',   // ← свой, из app/Auth
        'model' => App\Models\User::class,
    ],
],
```

Именно он подключает `LegacyUserProvider`, который умеет проверять старые
Werkzeug-хеши (`scrypt`, `pbkdf2`) и пересоздавать их в bcrypt. Без этой
строки перенесённые аккаунты не смогли бы войти.

Остальное стандартно: guard `web` (session), сброс пароля (таблица
`password_reset_tokens`, TTL 60 мин, throttle 60 с).

## cache.php — кэш

Драйвер по умолчанию — `database` (таблица `cache`). Используется
`TmdbService` для кэширования ответов TMDB. Также описаны `file`, `redis`,
`memcached`, `dynamodb`, `array` — на случай масштабирования.

## cors.php — CORS (важно для SPA)

Разрешает фронтенду (Next.js) обращаться к API с другого порта:

```php
'allowed_origins' => [
    'http://localhost:3000', 'http://localhost:3001', 'http://localhost:3002',
    'http://127.0.0.1:3000', 'http://127.0.0.1:3001', 'http://127.0.0.1:3002',
],
'supports_credentials' => true,   // ← разрешает cookie (auth)
```

**Зачем:** фронтенд и бэкенд — разные порты/домены; без CORS браузер заблокирует
запросы. `supports_credentials: true` позволяет отправлять cookie аутентификации.

## database.php — база данных

Подключение по умолчанию — **SQLite** (`database_path('database.sqlite')`).
Описаны также `mysql`, `mariadb`, `pgsql`, `sqlsrv` — чтобы на проде можно
было просто поменять `DB_CONNECTION` в `.env`. SQLite-настройки (внешние
ключи, WAL) дополнительно выставляются в `AppServiceProvider`.

## filesystems.php — файлы

Диски: `local` (private), `public` (с URL `/storage`), `s3` (облако).
Символическая ссылка `public/storage → storage/app/public` создаётся
командой `php artisan storage:link`. Используется для аватаров, постеров и
импортированных legacy-файлов.

## legacy.php — импорт старой БД (свой файл)

```php
'source'         => env('LEGACY_DATABASE'),       // путь к SQLite Flask
'admin_password' => env('LOCAL_ADMIN_PASSWORD'),  // пароль локального admin
```

Миниатюрный конфиг, который читает `BootstrapLocal` и `ImportLegacy`.
Связывает команду импорта с конкретным файлом старой базы и паролем админа.

## logging.php — логи

Канал по умолчанию — `stack` → `single` (файл `storage/logs/laravel.log`).
Доступны также `daily`, `slack`, `stderr`, `syslog`, `errorlog`, `null`.
На уровне Monolog; уровень — `LOG_LEVEL` (по умолчанию `debug`).

## mail.php — почта

Транспорт по умолчанию — **`log`** (письма пишутся в лог, не отправляются).
Это удобно для локальной разработки: сброс пароля «работает», но письмо
видимо только в логах. Для реальной отправки достаточно переключить на `smtp`.

## purifier.php — HTMLPurifier

Конфигурация пакета `mews/purifier` (очистка HTML). Определяет разрешённые
теги/атрибуты, кодировку UTF-8, кэш. В проекте используется для безопасной
обработки пользовательского HTML (например, описаний).

## queue.php — очереди

Драйвер по умолчанию — `database` (таблица `jobs`). Позволяет асинхронные
задачи (например, тяжёлый импорт) не блокировать HTTP-запрос. Остальные
драйверы (`sync`, `redis`, `beanstalkd`, `sqs`) описаны для масштабирования.

## sanctum.php — аутентификация SPA

Настройка Laravel Sanctum (stateful API): список доменов, которым разрешены
cookie-сессии (`localhost:3000` и т.д.), guard `web`. В проекте основной
аутентификацией является сессия через `auth.php`, Sanctum — запасной вариант
для SPA.

## services.php — сторонние сервисы

**Своё:** блок `tmdb`:

```php
'tmdb' => ['api_key' => env('TMDB_API_KEY')],
```

Именно его читает `TmdbService`. Также описаны `postmark`, `ses`, `resend`,
`slack` — стандартные, не используются.

## session.php — сессии

Драйвер по умолчанию — **`database`** (таблица `sessions`). Cookie: имя
`laravel_session`, `http_only: true`, `same_site: lax`. Используется guard
`web` для хранения вошедшего пользователя между запросами.

---

## Как это работает вместе (для презентации)

```
.env (переменные окружения)
   │
   ▼
config/*.php (14 файлов)
   │
   ├── app.php          → имя, env, frontend_url
   ├── auth.php         → legacy-eloquent (legacy-пароли)
   ├── cors.php         → разрешены порты 3000–3002 (SPA)
   ├── database.php     → sqlite по умолчанию
   ├── cache.php        → database (кэш TMDB)
   ├── session.php      → database (сессии)
   ├── queue.php        → database (очереди)
   ├── mail.php         → log (письма в лог)
   ├── services.php     → tmdb.api_key
   └── legacy.php       → путь к старой БД, пароль admin
   │
   ▼
Код приложения (AppServiceProvider, TmdbService, LegacyUserProvider, ...)
```

**Результат:** вся «магия» проекта — legacy-пароли, TMDB, CORS для SPA,
импорт старой БД — настраивается именно здесь, в `config/`.
