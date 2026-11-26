import type { Metadata, Viewport } from "next";
import { Geist } from "next/font/google";
import { Suspense } from "react";
import Link from "next/link";
import { cacheLife } from "next/cache";
import Providers from "./providers";
import Header from "@/components/Header";
import { Loading } from "@/components/UI";
import "./globals.css";

const geist = Geist({
  subsets: ["latin", "cyrillic"],
  display: "swap",
  variable: "--font-geist",
});

async function getCurrentYear() {
  "use cache";
  cacheLife("max");
  return new Date().getFullYear();
}

export const metadata: Metadata = {
  title: { default: "Rewatch — твой дневник кино", template: "%s · Rewatch" },
  description:
    "Фильмы и сериалы из TMDB, оценки, прогресс просмотра и личные коллекции.",
  metadataBase: new URL(
    process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3002",
  ),
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#0b0e14",
  colorScheme: "dark",
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const currentYear = await getCurrentYear();

  return (
    <html lang="ru">
      <body className={geist.variable}>
        <a className="skip-link" href="#content">
          К содержимому
        </a>
        <Providers>
          <Suspense fallback={<div className="header-placeholder" />}>
            <Header />
          </Suspense>
          <main id="content" className="container">
            <Suspense fallback={<Loading text="Загрузка страницы…" />}>
              {children}
            </Suspense>
          </main>
          <footer className="mt-20 border-t border-white/5 bg-gradient-to-b from-transparent to-[#0a0d12]">
            <div className="mx-auto w-full max-w-[1344px] px-6 py-12 sm:px-8">
              <div className="grid gap-10 md:grid-cols-[1.5fr_1fr_1fr]">
                <div>
                  <Link
                    href="/"
                    className="inline-flex items-center text-2xl font-bold tracking-tight text-white"
                  >
                    <svg
                      viewBox="0 0 32 32"
                      className="mr-2 size-7 text-gold"
                      aria-hidden="true"
                    >
                      <path
                        d="M25 10a11 11 0 1 0 1 11M25 3v8h-8"
                        stroke="currentColor"
                        strokeWidth="1.8"
                        fill="none"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                      <path
                        d="m13 10 9 6-9 6z"
                        stroke="currentColor"
                        strokeWidth="1.8"
                        fill="none"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </svg>
                    Rewatch<span className="text-gold">.</span>
                  </Link>
                  <p className="mt-3 max-w-xs text-sm leading-relaxed text-zinc-500">
                    Твой личный дневник кино. Сохраняй фильмы, отмечай
                    просмотренное, собирай коллекции.
                  </p>
                </div>
                <div>
                  <h3 className="mb-4 text-xs font-semibold uppercase tracking-widest text-zinc-400">
                    Разделы
                  </h3>
                  <ul className="space-y-2.5 text-sm">
                    <li>
                      <Link
                        href="/catalog"
                        className="text-zinc-400 transition-colors hover:text-gold"
                      >
                        Каталог
                      </Link>
                    </li>
                    <li>
                      <Link
                        href="/library"
                        className="text-zinc-400 transition-colors hover:text-gold"
                      >
                        Сообщество
                      </Link>
                    </li>
                    <li>
                      <Link
                        href="/collections"
                        className="text-zinc-400 transition-colors hover:text-gold"
                      >
                        Коллекции
                      </Link>
                    </li>
                    <li>
                      <Link
                        href="/stats"
                        className="text-zinc-400 transition-colors hover:text-gold"
                      >
                        Статистика
                      </Link>
                    </li>
                  </ul>
                </div>
                <div>
                  <h3 className="mb-4 text-xs font-semibold uppercase tracking-widest text-zinc-400">
                    Сообщество
                  </h3>
                  <ul className="space-y-2.5 text-sm">
                    <li>
                      <Link
                        href="/suggest"
                        className="text-zinc-400 transition-colors hover:text-gold"
                      >
                        Предложить фильм
                      </Link>
                    </li>
                    <li>
                      <Link
                        href="/moderation"
                        className="text-zinc-400 transition-colors hover:text-gold"
                      >
                        Мои заявки
                      </Link>
                    </li>
                    <li>
                      <a
                        href="https://www.themoviedb.org"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-zinc-400 transition-colors hover:text-gold"
                      >
                        Данные TMDB
                      </a>
                    </li>
                  </ul>
                </div>
              </div>
              <div className="mt-10 flex flex-col items-start justify-between gap-3 border-t border-white/5 pt-6 text-xs text-zinc-600 sm:flex-row sm:items-center">
                <p>© {currentYear} Rewatch. Все истории — у тебя.</p>
                <p>Сделано с любовью к кино</p>
              </div>
            </div>
          </footer>
        </Providers>
      </body>
    </html>
  );
}