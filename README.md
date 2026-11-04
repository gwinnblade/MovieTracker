# MovieTracker

![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=next.js)
![Laravel](https://img.shields.io/badge/Laravel-13-FF2D20?logo=laravel)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript)
![Tailwind](https://img.shields.io/badge/Tailwind-4-06B6D4?logo=tailwindcss)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?logo=sqlite)

---

## О проекте

MovieTracker — это современное fullstack-приложение, вдохновленное Кинопоиском и Letterboxd. Пользователи могут искать фильмы через TMDB API, создавать заявки на добавление в каталог, вести персональные списки с оценками и делиться ими по публичным ссылкам.

Проект разрабатывался с фокусом на **чистую архитектуру**, **производительность** и **профессиональный UX**.

---

## Технологический стек

### Frontend
- **Next.js 16** (App Router, Server Components)
- **TypeScript** — строгая типизация
- **Tailwind CSS 4** — utility-first стилизация
- **TanStack React Query** — кэширование и управление серверным состоянием
- **Framer Motion** — плавные анимации
- **react-hot-toast** — уведомления
- **Heroicons** — иконки

### Backend
- **Laravel 13** — PHP-фреймворк
- **Laravel Sanctum** — API-аутентификация
- **SQLite** — легковесная БД для разработки
- **TMDB API** — внешний источник данных о фильмах

### DevOps
- **Docker + Docker Compose** — контейнеризация
- **Nginx** — reverse proxy и раздача статики

---

## Ключевые возможности

### Для пользователей
- **Умный поиск** фильмов через TMDB API с автодополнением
- **Заявки на модерацию** — пользователи предлагают новые фильмы
- **Персональные отметки** — статус (смотрю/планирую/брошено), оценка 1-10, личная заметка
- **Списки** — создание тематических подборок с возможностью публикации по ссылке
- **Профиль** — управление данными и просмотр активности

### Для каталога
- **Автоматическое скачивание постеров и фото актёров** с TMDB при модерации
- **Страницы персон** (`/persons/[id]`) с полной фильмографией, разделённой на режиссуру и актёрские работы
- **Блок "Другие фильмы режиссёра"** с горизонтальной прокруткой
- **Фильтрация** по типу, жанру и году выпуска
- **Кликабельные персоны** — от актёра к его фильмографии в один клик

### Производительность и UX
- **Оптимизация изображений** через `next/image` (WebP, lazy loading, нулевой CLS)
- **Кэширование справочников** на 24 часа через React Query
- **Rate Limiting** — защита API от спама (120 req/min для публичных, 10 для auth)
- **Кастомные страницы ошибок** (404/500) с анимациями
- **Адаптивный дизайн** — от мобильных до 4K

---

## Быстрый старт

### Требования
- [Docker](https://www.docker.com/) и Docker Compose
- [Node.js 20+](https://nodejs.org/) (опционально, для локальной разработки без Docker)

### 1. Клонирование репозитория
```bash
git clone https://github.com/your-username/MovieTracker.git
cd MovieTracker
```

### 2. Настройка переменных окружения

Скопируйте файлы примеров и заполните их своими данными:

```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

> **Важно:** Для работы поиска и загрузки данных откройте `backend/.env` и укажите ваш реальный ключ API в переменной `TMDB_API_KEY`. Получить его бесплатно можно на [themoviedb.org](https://www.themoviedb.org/).

### 3. Запуск через Docker (рекомендуемый способ)

Этот метод автоматически соберёт образы, создаст базу данных SQLite и запустит миграции:

```bash
docker-compose up -d --build
```

После завершения сборки приложение будет доступно по адресам:

- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:8080

---

## Локальная разработка (без Docker)

Если вы предпочитаете запускать сервисы напрямую на вашей машине:

### Backend (Laravel)

```bash
cd backend
composer install
cp .env.example .env
php artisan key:generate
php artisan migrate
php artisan serve --port=8080
```

### Frontend (Next.js)

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Приложение будет доступно на http://localhost:3000

---

## Основные переменные окружения

| Переменная | Описание | Пример |
| --- | --- | --- |
| `TMDB_API_KEY` | Ключ чтения (v4 Read Access Token) от TMDB | `eyJhbG...` |
| `NEXT_PUBLIC_API_URL` | Базовый URL бэкенда для фронтенда | `http://localhost:8080/api` |
| `DB_CONNECTION` | Тип подключения к БД (по умолчанию `sqlite`) | `sqlite` |

---

## Структура проекта

```text
MovieTracker/
├── backend/            # Laravel API
│   ├── app/
│   ├── config/
│   ├── database/
│   ├── routes/
│   └── .env.example
├── frontend/           # Next.js приложение
│   ├── app/
│   ├── components/
│   ├── public/
│   └── .env.example
├── docker-compose.yml
└── README.md
```

---

## Ролевая модель

В приложении реализована трёхуровневая система доступа:

- **Гость / Пользователь:** поиск, просмотр, создание личных списков и заявок на добавление фильмов.
- **Администратор:** полный доступ к управлению контентом и пользователями.

> Для создания первого администратора используйте Laravel Tinker:
>
> ```bash
> php artisan tinker
> ```
>
> ```php
> User::create([
>     'login'    => 'admin',
>     'email'    => 'admin@test.com',
>     'password' => Hash::make('password'),
>     'role'     => 'admin',
> ]);
> ```


## Важные примечания по запуску

1. **VPN**: Для корректной работы с API TMDB (поиск фильмов, загрузка постеров и фото актёров) **требуется активное VPN-подключение**, так как некоторые провайдеры блокируют запросы к `api.themoviedb.org` и `image.tmdb.org`.
2. **База данных**: Проект использует SQLite. При первом запуске база создается автоматически внутри контейнера. Если возникнут ошибки, выполните полную очистку: `docker-compose down -v`, удалите файл `backend/database/database.sqlite` и запустите `docker-compose up -d --build`.
3. **Порты**: Фронтенд доступен на `http://localhost:3001`, бэкенд API на `http://localhost:8080`.

## Быстрый старт для разработчиков

1. Убедитесь, что у вас установлен **Docker Desktop** и запущен **VPN** (для доступа к API TMDB).
2. Скопируйте файл `.env.example` в `.env` (в папках `backend` и `frontend`) и настройте переменные.
3. Запустите проект:
   ```bash
   docker-compose up -d --build
    ```
4. Инициализируйте базу данных (это автоматически создаст тестовые данные и учетную запись администратора):
   ```bash
      docker-compose exec backend php artisan db:seed
   ```
5. Откройте http://localhost:3001 Администратор по умолчанию: admin / SuperAdmin2026!