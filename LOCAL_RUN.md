# Локальный запуск Rewatch

Рабочая папка переноса: `/home/agxny/Downloads/MovieTracker-port`. Ветка: `testinganother-laravel-next`, создана от `testinganother`.

```bash
cd /home/agxny/Downloads/MovieTracker-port
./start-local.sh --build
```

- Интерфейс: http://localhost:3002
- API и изображения: http://localhost:8081
- Администратор: `admin`, пароль — `LOCAL_ADMIN_PASSWORD` в `backend/.env`.
- Импортированные аккаунты сохраняют прежние логины, email и пароли.

Порты 3002 и 8081 выбраны для одновременного запуска с ранее поднятой версией товарища на 3001 и 8080.

## TMDB и VPN

В `backend/.env` нужен `TMDB_API_KEY` с **TMDB API Read Access Token (v4)**. Токен остаётся на сервере.

На этом компьютере обычный DNS возвращал `127.0.0.1` для доменов TMDB даже при включённом VPN. `scripts/configure-local-network.mjs` получает настоящие IPv4 через DNS-over-HTTPS и записывает их в игнорируемый `docker-compose.override.yml`. Настройки DNS компьютера не меняются.

Постеры и фотографии загружаются через `/tmdb-images/` на сервере. Проверка TLS включена; cookies и авторизация сайта не передаются серверу изображений. Если VPN или адреса изменились, повторите `./start-local.sh`.

## Данные

Рабочая БД: `backend/database/database.sqlite`. Загрузки: `backend/storage/app/public`. Эти папки подключены как тома и сохраняются при пересборке.

`legacy/movietracker.db` — исходная база Flask. Она подключена только для чтения. Импорт запускается один раз для каждого SHA-256 исходного файла. Он сохраняет связи аккаунтов, коллекций, оценок, прогресса и заметок. См. [MIGRATION.md](MIGRATION.md).

Чтобы дать модераторские права существующему аккаунту:

```bash
docker compose exec backend php artisan user:moderator ЛОГИН
```

## Восстановление пароля

В локальном режиме используется `MAIL_MAILER=log`, как консольный вывод ссылки в прежней Flask-версии. Письмо и ссылка записываются в приватный журнал `backend/storage/logs/laravel.log`.

Для реальной отправки писем задайте `MAIL_MAILER=smtp`, `MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_FROM_ADDRESS` в `backend/.env`, затем перезапустите контейнеры. Ссылка действует 60 минут и используется только один раз.

## Проверки и остановка

```bash
docker compose ps
docker compose logs --tail=50 backend frontend
docker compose --profile test run --build --rm --no-deps tests
docker compose stop
```

Тестовый контейнер не подключает рабочую базу: все тесты выполняются в SQLite в памяти.
