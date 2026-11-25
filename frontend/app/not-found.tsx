import Link from "next/link";
export default function NotFound() {
  return (
    <div className="empty-state panel">
      <span className="eyebrow">404</span>
      <h1>Эта история потерялась</h1>
      <p>Страница не найдена.</p>
      <Link className="button" href="/catalog">
        Найти другую историю
      </Link>
    </div>
  );
}
