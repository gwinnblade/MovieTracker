# Интерфейс Rewatch

TypeScript / React 19 / Next.js 16 / Tailwind CSS 4 / TanStack Query. Тёмный интерфейс дневника кино.

Для разработки при запущенном API:

```bash
npm ci --legacy-peer-deps
npm run dev -- --hostname 127.0.0.1 --port 3002
```

API задаётся через `NEXT_PUBLIC_API_URL` **без `/api`**. По умолчанию: `http://localhost:8081`. Публичные переменные окружения включаются в сборку, поэтому после их изменения нужно пересобрать контейнер.

Проверки: `npm run lint`, `npm run build`. Проверка TypeScript при сборке включена.

Общий запуск и настройка TMDB: [LOCAL_RUN.md](../LOCAL_RUN.md).
