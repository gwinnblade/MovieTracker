// frontend/components/ui/Footer.tsx
'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import {
  FilmIcon,
  ArrowUpIcon,
  HeartIcon,
} from '@heroicons/react/24/outline';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

const LINKS = [
  { href: '/catalog', label: 'Каталог' },
  { href: '/random', label: 'Случайное' },
  { href: '/suggest', label: 'Предложить' },
  { href: '/terms', label: 'Условия' },
  { href: '/privacy', label: 'Конфиденциальность' },
];

const SHORTCUTS = [
  { keys: ['/'], label: 'поиск' },
  { keys: ['Esc'], label: 'закрыть' },
];

export default function Footer() {
  const [currentYear, setCurrentYear] = useState(2024);
  const prefersReduced = useReducedMotion();
  const [showTop, setShowTop] = useState(false);

  useEffect(() => {
    setCurrentYear(new Date().getFullYear());
    const onScroll = () => setShowTop(window.scrollY > 600);
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const scrollToTop = () => {
    window.scrollTo({
      top: 0,
      behavior: prefersReduced ? 'auto' : 'smooth',
    });
  };

  return (
    <footer
      role="contentinfo"
      className="mt-auto border-t border-[var(--line)] bg-[var(--bg-primary)] text-[var(--text-primary)]"
    >
      <div className="max-w-[1400px] mx-auto px-6 lg:px-10">
        {/* ===== Верхняя редакционная полоса ===== */}
        <div className="pt-8 lg:pt-10">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
            <span>MovieTracker — Кинодневник</span>
            <span className="hidden sm:inline">Est. 2024</span>
          </div>
        </div>

        {/* ===== Основной блок: бренд + навигация ===== */}
        <div className="grid lg:grid-cols-12 gap-10 lg:gap-16 py-14 lg:py-20">
          {/* Бренд и слоган */}
          <div className="lg:col-span-6">
            <Link
              href="/"
              className="group inline-flex items-center gap-3"
              aria-label="MovieTracker — на главную"
            >
              <FilmIcon
                className="w-5 h-5 text-[var(--accent-yellow)] transition-transform duration-500 group-hover:rotate-[-8deg]"
                aria-hidden="true"
              />
              <span className="font-serif text-3xl sm:text-4xl tracking-[-0.02em]">
                MovieTracker
                <span className="text-[var(--accent-yellow)]">.</span>
              </span>
            </Link>
            <p className="mt-6 max-w-md text-base sm:text-lg text-[var(--text-secondary)] leading-relaxed">
              Кинодневник для тех, кто помнит, что смотрел
            </p>
          </div>

          {/* Навигация — вертикальный список с индексами */}
          <nav
            aria-label="Ссылки в подвале"
            className="lg:col-span-6"
          >
            <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-5">
              Разделы
            </p>
            <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-8">
              {LINKS.map((l, i) => (
                <li key={l.href} className="border-b border-[var(--line)]">
                  <Link
                    href={l.href}
                    className="group flex items-center justify-between py-3"
                  >
                    <span className="flex items-baseline gap-3">
                      <span className="font-mono text-[10px] tracking-[0.2em] text-[var(--text-muted)]">
                        {String(i + 1).padStart(2, '0')}
                      </span>
                      <span className="font-serif text-base text-[var(--text-primary)] group-hover:italic transition-[font-style] duration-300">
                        {l.label}
                      </span>
                    </span>
                    <span className="text-[var(--text-muted)] opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                      →
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </nav>
        </div>

        {/* ===== Нижняя полоса: копирайт + шорткаты ===== */}
        <div className="border-t border-[var(--line)] py-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] flex flex-wrap items-center gap-x-3 gap-y-1.5">
            <span>© {currentYear} MovieTracker</span>
            <span aria-hidden="true" className="text-[var(--text-muted)]/40">·</span>
            <span className="inline-flex items-center gap-1.5 normal-case tracking-normal">
              Сделано с
              <HeartIcon
                className="w-3 h-3 text-[var(--accent-red)]"
                aria-label="любовью"
              />
              к кино
            </span>
          </p>

          {SHORTCUTS.length > 0 && (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
              <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] hidden sm:inline">
                Клавиши
              </span>
              <ul className="flex flex-wrap items-center gap-x-4 gap-y-2">
                {SHORTCUTS.map((s) => (
                  <li
                    key={s.label}
                    className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)]"
                  >
                    <span className="inline-flex items-center gap-1">
                      {s.keys.map((k, i) => (
                        <Kbd key={i}>{k}</Kbd>
                      ))}
                    </span>
                    <span>{s.label}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>

      {/* ===== Кнопка «наверх» ===== */}
      <AnimatePresence>
        {showTop && (
          <motion.button
            type="button"
            onClick={scrollToTop}
            aria-label="Наверх"
            title="Наверх"
            initial={prefersReduced ? false : { opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={prefersReduced ? undefined : { opacity: 0, y: 16 }}
            transition={{ duration: 0.4, ease: EASE_OUT }}
            className="group fixed bottom-6 right-6 z-40 w-12 h-12 rounded-full bg-[var(--text-primary)] text-[var(--bg-primary)] flex items-center justify-center transition-transform duration-500 hover:scale-110 hover:rotate-[-8deg]"
          >
            <ArrowUpIcon className="w-5 h-5" aria-hidden="true" />
          </motion.button>
        )}
      </AnimatePresence>
    </footer>
  );
}

/* ---------- Kbd ---------- */

function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex items-center justify-center min-w-[1.5rem] h-6 px-2 border border-[var(--line)] text-[10px] font-mono font-medium text-[var(--text-secondary)] leading-none">
      {children}
    </kbd>
  );
}