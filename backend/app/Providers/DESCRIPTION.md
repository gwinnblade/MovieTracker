# Провайдер приложения (app/Providers/AppServiceProvider)

**Service Provider** — класс, который Laravel запускает при старте приложения
(до первого запроса). Это «точка настройки»: здесь подключаются сервисы,
настраиваются глобальные поведения. В проекте один провайдер —
`AppServiceProvider`, и он делает три вещи в методе `boot()`.

## 1. Провайдер аутентификации с legacy-паролями

```php
Auth::provider('legacy-eloquent', function ($app, array $config) {
    return new LegacyUserProvider($app['hash'], $config['model']);
});
```

Регистрирует собственный провайдер пользователей `LegacyUserProvider`
(из папки `app/Auth`) под именем `legacy-eloquent`. Благодаря ему стандартный
вход Laravel умеет проверять **старые Werkzeug-хеши** (`scrypt`, `pbkdf2`) из
перенесённой Flask-базы и автоматически пересоздавать их в bcrypt при первом
успешном входе. Без этой строки старые аккаунты после миграции не смогли бы
войти.

## 2. Ссылка для сброса пароля

```php
ResetPassword::createUrlUsing(fn ($user, string $token) =>
    rtrim(config('app.frontend_url'), '/').'/reset-password/'.$token.'?email='.rawurlencode($user->email));
```

Переходит с «сырого» токена на **готовый URL** страницы сброса пароля:
`<frontend_url>/reset-password/<token>?email=<email>`. Это важно, потому что
фронтенд — отдельное SPA (Next.js), и письмо должно вести сразу на нужную
страницу с уже подставленным токеном и email.

## 3. Настройка SQLite (только если БД — SQLite)

```php
if (config('database.default') === 'sqlite') { ... }
```

Если в проекте используется SQLite, выставляются PRAGMA-настройки:

| PRAGMA | Что делает |
|---|---|
| `foreign_keys = ON` | включает внешние ключи (по умолчанию в SQLite выключены) |
| `journal_mode = WAL` | Write-Ahead Logging — чтение не блокирует запись |
| `synchronous = NORMAL` | баланс между надёжностью и скоростью записи |
| `busy_timeout = 5000` | ждать до 5 секунд, если БД занята другим процессом |

**Зачем:** SQLite без этих настроек уязвим к блокировкам и не проверяет
целостность связей; PRAGMA делают локальный/контейнерный запуск предсказуемым.

## Как это работает (для презентации)

```
Старт приложения (php artisan serve / docker)
   │
   ▼
AppServiceProvider::boot()
   ├── регистрирует LegacyUserProvider (legacy-пароли)
   ├── настраивает URL сброса пароля для SPA
   └── если SQLite — выставляет PRAGMA
   │
   ▼
Приложение готово к работе
```
