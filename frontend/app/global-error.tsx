"use client";
export default function GlobalError({ reset }: { reset: () => void }) {
  return (
    <html lang="ru">
      <body>
        <h1>Не удалось открыть Rewatch</h1>
        <button onClick={reset}>Попробовать снова</button>
      </body>
    </html>
  );
}
