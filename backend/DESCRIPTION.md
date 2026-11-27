# Корень бэкенда (backend/)

Файлы в корне `backend/` — «обвязка» приложения: как оно запускается,
упаковывается в Docker, где берутся настройки и как собирается фронтенд.
Папки (`app/`, `config/`, `database/`, `routes/` и др.) описаны отдельно.

Проект называется **Rewatch** (`APP_NAME=Rewatch`, composer `gwinnblade/rewatch`).
Стек: **PHP 8.4 / Laravel 12 / Sanctum / SQLite**.

## Краткая таблица файлов

| Файл | Назначение |
|---|---|
| `artisan` | точка входа в консоль (CLI) |
| `composer.json` / `composer.lock` | зависимости PHP и их точные версии |
| `Dockerfile` | образ контейнера (PHP-FPM + Nginx + Supervisor) |
| `nginx.conf` | конфиг веб-сервера (порт 8000, прокси TMDB) |
| `supervisord.conf` | менеджер процессов внутри контейнера |
| `.env` / `.env.example` | переменные окружения (реальные / шаблон) |
| `package.json` | зависимости npm (Vite, Tailwind, axios) |
| `vite.config.js` | сборка ассетов (Vite + laravel-vite-plugin) |
| `tailwind.config.js` | настройки Tailwind CSS |
| `postcss.config.js` | плагин PostCSS (tailwind + autoprefixer) |
| `phpunit.xml` | конфигурация тестов |
| `README.md` | краткая справка по API и командам |
| `.editorconfig` | единые правила форматирования |
| `.gitignore` / `.gitattributes` | что не коммитить / как diff |
| `.dockerignore` | что не копировать в образ |

---

## Точка входа и зависимости

### artisan
CLI-обёртка: подгружает `vendor/autoload.php`, запускает `bootstrap/app.php`
и обрабатывает команду. Именно через неё работают все `php artisan ...`.

### composer.json / composer.lock
- **`composer.json`** — декларации зависимостей: `laravel/framework ^12.69`,
  `laravel/sanctum`, `mews/purifier` (очистка HTML), PHP `^8.4`. В `scripts`
  есть удобная команда `dev` (одновременно сервер + очередь + логи + Vite).
- **`composer.lock`** — зафиксированные точные версии всех пакетов, чтобы
  сборка была воспроизводимой.

---

## Docker / деплой

### Dockerfile
Один образ на два этапа (`runtime` и `test`):
1. База `php:8.4-fpm`, ставит расширения: `pdo_sqlite`, `gd`, `intl`, `zip`, **`ffi`**
   (нужен для проверки legacy-паролей через OpenSSL).
2. Ставит Composer, копирует код, создаёт папки `storage/*`.
3. Копирует `nginx.conf` и `supervisord.conf`.
4. **CMD**: `touch database.sqlite → migrate --force → app:bootstrap → supervisord -n`.

> То есть при старте контейнера база мигрируется и запускается `app:bootstrap`
> (словари + импорт legacy + локальный админ) — всё автоматически.

### nginx.conf
Веб-сервер на порту **8000**:
- `location /` → отдаёт Laravel (`index.php`).
- `location ~ \.php$` → PHP-FPM (`127.0.0.1:9000`).
- **`location /tmdb-images/`** — прокси на `image.tmdb.org/t/p/`: постеры TMDB
  отдаются «с нашего домена», чтобы не было CORS-проблем у фронтенда.

### supervisord.conf
Менеджер процессов внутри контейнера (всё в одном контейнере):
- `php-fpm` — исполняет PHP.
- `nginx` — веб-сервер.
- `laravel-queue` — `queue:work` (очередные задачи).
- `laravel-scheduler` — `schedule:work` (планировщик).

Все с `autorestart=true`, логи в stdout/stderr.

---

## Переменные окружения

### .env / .env.example
`.env` — реальные значения (в `.gitignore`), `.env.example` — шаблон.
Ключевые для проекта:
- `APP_NAME=Rewatch`, `APP_URL=http://localhost:8081`
- `DB_CONNECTION=sqlite`, `DB_DATABASE=/var/www/backend/database/database.sqlite`
- `LEGACY_DATABASE=/var/www/legacy/movietracker.db` — путь к старой БД Flask
- `FRONTEND_URL=http://localhost:3002` — адрес SPA
- `TMDB_API_KEY=`, `LOCAL_ADMIN_PASSWORD=` — ключ TMDB и пароль локального админа
- `SESSION_DRIVER=database`, `CACHE_STORE=file`, `QUEUE_CONNECTION=sync`

---

## Сборка фронтенда (Vite + Tailwind)

| Файл | Роль |
|---|---|
| `package.json` | npm-зависимости: `vite`, `tailwindcss`, `axios`, `laravel-vite-plugin` |
| `vite.config.js` | входные точки `resources/css/app.css`, `resources/js/app.js` |
| `tailwind.config.js` | скан `resources/**`, шрифт Figtree |
| `postcss.config.js` | пайплайн PostCSS: tailwind + autoprefixer |

> Основной UI живёт во фронтенде (Next.js); здесь собирается только «обёртка»
> Laravel (welcome-страница и Blade-шаблон).

---

## Тесты

### phpunit.xml
Два набора: `Unit` (`tests/Unit`) и `Feature` (`tests/Feature`).
Для тестов принудительно: `DB_DATABASE=:memory:` (SQLite в памяти),
`CACHE_STORE=array`, `SESSION_DRIVER=array`, `MAIL_MAILER=array` — т.е.
тесты не трогают реальную БД и не шлют письма. Запуск: `php artisan test`.

---

## Служебные / соглашения

| Файл | Что делает |
|---|---|
| `README.md` | стек, основные маршруты API, команды (`app:bootstrap`, `legacy:import`, `user:moderator`), как гонять тесты |
| `.editorconfig` | единые отступы (4 пробела), UTF-8, LF, финальный newline |
| `.gitignore` | не коммитить: `vendor/`, `node_modules/`, `.env`, `storage/*`, `*.sqlite` |
| `.gitattributes` | `text=auto eol=lf`, diff для `.php`/`.css`/`.md`; экспорт-игноры |
| `.dockerignore` | не копировать в образ: `.env`, `vendor`, `storage`, `*.sqlite*`, логи |

---

## Как это работает вместе (для презентации)

```
Dockerfile  ──►  образ php:8.4-fpm + nginx + supervisor + ffi
   │
   ├── CMD: migrate → app:bootstrap → supervisord
   │
   ▼
supervisord.conf
   ├── php-fpm      (исполняет PHP)
   ├── nginx        (порт 8000, прокси /tmdb-images/)
   ├── laravel-queue
   └── laravel-scheduler
   │
   ▼
artisan  ──►  bootstrap/app.php  ──►  routes/  ──►  app/
   ▲
   └── .env (настройки) + composer.json (зависимости)
```

**Результат:** весь бэкенд упакован в один Docker-образ; при старте база
сама мигрируется и наполняется (`app:bootstrap`), а Nginx отдаёт API и
проксирует постеры TMDB.
