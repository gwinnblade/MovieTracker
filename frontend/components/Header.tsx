"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import toast from "react-hot-toast";
import { useAuth } from "./Auth";
import { errorMessage } from "@/lib/api";

export default function Header() {
  const path = usePathname();
  const router = useRouter();
  const { user, loading, logout } = useAuth();
  const [menu, setMenu] = useState(false);
  const nav = [
    ["/catalog", "Открыть кино"],
    ["/library", "Каталог"],
    ["/entries", "Мой список"],
    ["/collections", "Коллекции"],
    ["/stats", "Статистика"],
  ];
  const search = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const q = String(
      new FormData(event.currentTarget).get("query") || "",
    ).trim();
    if (q.length >= 2) {
      router.push("/search?q=" + encodeURIComponent(q));
      setMenu(false);
    }
  };
  return (
    <header className="site-header">
      <div className="header-inner">
        <Link href="/" className="brand" aria-label="Rewatch — главная">
          <svg viewBox="0 0 32 32" aria-hidden="true">
            <path d="M25 10a11 11 0 1 0 1 11M25 3v8h-8" />
            <path d="m13 10 9 6-9 6z" />
          </svg>
          Rewatch<span className="brand-dot">.</span>
        </Link>
        <button
          className="icon-button mobile-toggle"
          aria-label="Меню"
          aria-expanded={menu}
          onClick={() => setMenu(!menu)}
        >
          ☰
        </button>
        <div className={"header-content " + (menu ? "open" : "")}>
          <nav aria-label="Главное меню">
            {nav.map(([href, text]) => (
              <Link
                key={href}
                href={href}
                onClick={() => setMenu(false)}
                className={path.startsWith(href) ? "active" : ""}
              >
                {text}
              </Link>
            ))}
          </nav>
          <form onSubmit={search} className="header-search" role="search">
            <input
              name="query"
              placeholder="Найти фильм…"
              aria-label="Поиск по TMDB"
              minLength={2}
              required
            />
            <button aria-label="Искать">⌕</button>
          </form>
          <div className="header-account">
            {!loading &&
              (user ? (
                <>
                  <Link href="/profile" className="account-link">
                    {user.name}
                  </Link>
                  <button
                    className="text-button"
                    onClick={async () => {
                      try {
                        await logout();
                        router.push("/");
                      } catch (error) {
                        toast.error(errorMessage(error));
                      }
                    }}
                  >
                    Выйти
                  </button>
                </>
              ) : (
                <Link className="button small" href="/login">
                  Войти
                </Link>
              ))}
          </div>
        </div>
      </div>
    </header>
  );
}
