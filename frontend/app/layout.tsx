import type { Metadata, Viewport } from "next";
import { Suspense } from "react";
import Link from "next/link";
import Providers from "./providers";
import Header from "@/components/Header";
import "./globals.css";

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
  themeColor: "#0f1117",
  colorScheme: "dark",
};
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="ru">
      <body>
        <a className="skip-link" href="#content">
          К содержимому
        </a>
        <Providers>
          <Suspense fallback={<div className="header-placeholder" />}>
            <Header />
          </Suspense>
          <main id="content" className="container">
            <Suspense
              fallback={<div className="loading">Загрузка страницы…</div>}
            >
              {children}
            </Suspense>
          </main>
          <footer className="site-footer">
            <div>
              <Link href="/" className="brand">
                Rewatch<span className="brand-dot">.</span>
              </Link>
              <p>Сохраняй кино. Продолжай истории.</p>
            </div>
            <div className="footer-links">
              <Link href="/suggest">Предложить фильм</Link>
              <Link href="/moderation">Мои заявки</Link>
              <span>Данные о фильмах: TMDB</span>
            </div>
          </footer>
        </Providers>
      </body>
    </html>
  );
}
