"use client";
export default function ErrorPage({ reset }: { reset: () => void }) {
  return (
    <div className="empty-state panel">
      <h1>Не удалось открыть страницу</h1>
      <button className="button" onClick={reset}>
        Попробовать снова
      </button>
    </div>
  );
}
