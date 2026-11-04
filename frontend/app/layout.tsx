// frontend/app/layout.tsx
import type { Metadata, Viewport } from "next";
import { Space_Grotesk, JetBrains_Mono } from "next/font/google";
import { Suspense } from "react";
import "./globals.css";
import Providers from "./providers";
import Header from "@/components/ui/Header";
import Footer from "@/components/ui/Footer";

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-space-grotesk",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin", "cyrillic"],
  display: "swap",
  variable: "--font-jetbrains-mono",
});

const SITE_URL =
  process.env.NEXT_PUBLIC_SITE_URL?.replace(/\/$/, "") ?? "http://localhost:3000";

const SITE_NAME = "MovieTracker";
const SITE_DESCRIPTION =
  "Отмечайте просмотренные фильмы, собирайте списки и делитесь ими с друзьями";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: `${SITE_NAME} — дневник кино`,
    template: `%s · ${SITE_NAME}`,
  },
  description: SITE_DESCRIPTION,
  applicationName: SITE_NAME,
  openGraph: {
    type: "website",
    locale: "ru_RU",
    siteName: SITE_NAME,
    title: SITE_NAME,
    description: SITE_DESCRIPTION,
    url: "/",
  },
  twitter: {
    card: "summary_large_image",
    title: SITE_NAME,
    description: SITE_DESCRIPTION,
  },
  robots: {
    index: true,
    follow: true,
  },
  icons: {
    icon: "/favicon.ico",
  },
  formatDetection: {
    telephone: false,
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
  themeColor: "#faf8f2",
  colorScheme: "light",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="ru"
      className={`${spaceGrotesk.variable} ${jetbrainsMono.variable}`}
    >
      <body className="font-sans bg-[var(--bg-primary)] text-[var(--text-primary)] antialiased min-h-dvh flex flex-col">
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-[100] focus:px-4 focus:py-2 focus:bg-[var(--accent-yellow)] focus:text-black focus:font-mono focus:text-[11px] focus:uppercase focus:tracking-[0.2em] focus:border focus:border-black"
        >
          К основному содержимому
        </a>

        <Providers>
          <Suspense fallback={<div className="h-16" aria-hidden="true" />}>
            <Header />
          </Suspense>

          <main
            id="main-content"
            tabIndex={-1}
            className="flex-1 outline-none"
          >
            <Suspense fallback={<PageFallback />}>{children}</Suspense>
          </main>
          <Footer />
        </Providers>
      </body>
    </html>
  );
}

function PageFallback() {
  return (
    <div
      role="status"
      aria-live="polite"
      className="min-h-[70vh] bg-[var(--bg-primary)]"
    >
      <span className="sr-only">Загрузка страницы</span>

      <div className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] animate-pulse">
            <div className="h-2.5 w-28 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-2.5 w-20 bg-[var(--bg-tertiary)] rounded" />
          </div>
        </div>

        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-14 lg:pb-20 animate-pulse">
          <div className="space-y-4 max-w-3xl">
            <div className="h-2.5 w-24 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-16 sm:h-24 lg:h-32 w-full max-w-2xl bg-[var(--bg-tertiary)] rounded" />
            <div className="h-16 sm:h-24 lg:h-32 w-3/4 max-w-xl bg-[var(--bg-tertiary)] rounded" />
          </div>

          <div className="mt-12 space-y-2.5 max-w-xl">
            <div className="h-3.5 w-full bg-[var(--bg-tertiary)] rounded" />
            <div className="h-3.5 w-4/5 bg-[var(--bg-tertiary)] rounded" />
          </div>
        </div>
      </div>
    </div>
  );
}