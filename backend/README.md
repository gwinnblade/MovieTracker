# Rewatch API

PHP 8.4 / Laravel 12.72 / Sanctum / SQLite. Локальный запуск выполняется через Docker из корня репозитория. [Инструкция](../LOCAL_RUN.md).

Основные маршруты: `/api/v1/auth`, `/api/v1/tmdb`, `/api/v1/media`, `/api/v1/entries`, `/api/v1/lists`, `/api/v1/profile`, `/api/v1/moderation/requests`.

`app:bootstrap` создаёт словари, импортирует заданную исходную базу и при необходимости создаёт локального администратора с паролем из окружения. `legacy:import` сохраняет данные Flask; `user:moderator` назначает роль.

Тесты: `docker compose --profile test run --build --rm --no-deps tests` из корня. У тестового контейнера нет тома рабочей БД.
