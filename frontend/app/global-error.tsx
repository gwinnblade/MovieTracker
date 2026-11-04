// frontend/app/global-error.tsx
'use client';

import { useEffect } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { ArrowRightIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const EASE_EDITORIAL = [0.76, 0, 0.24, 1] as const;

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const prefersReduced = useReducedMotion();

  useEffect(() => {
    console.error('Global error:', error);
  }, [error]);

  return (
    <html lang="ru">
      <body className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)] antialiased">
        {/* ============ MASTHEAD ============ */}
        <div className="border-b border-[var(--line)]">
          <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
            <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
              <span>MovieTracker</span>
              <span className="hidden sm:inline">Критическая ошибка</span>
            </div>
          </div>
        </div>

        {/* ============ HERO ============ */}
        <main className="relative overflow-hidden">
          {/* Едва заметная текстура */}
          <div
            aria-hidden
            className="pointer-events-none absolute inset-0 opacity-[0.03]"
            style={{
              backgroundImage:
                'linear-gradient(var(--line) 1px, transparent 1px), linear-gradient(90deg, var(--line) 1px, transparent 1px)',
              backgroundSize: '64px 64px',
              maskImage:
                'radial-gradient(ellipse 70% 60% at 50% 40%, black 30%, transparent 80%)',
            }}
          />

          <div className="relative max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-20 lg:pb-28">
            <div className="grid lg:grid-cols-12 gap-10 lg:gap-8 items-end">
              {/* Левая колонка — гигантская editorial типографика */}
              <motion.div
                className="lg:col-span-7 min-w-0"
                initial={prefersReduced ? false : { opacity: 0, y: 24 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 1, ease: EASE_OUT }}
              >
                <div className="flex items-center gap-3 mb-8">
                  <span className="h-px w-10 bg-[var(--text-primary)]" />
                  <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-secondary)]">
                    Что-то пошло не так
                  </span>
                </div>

                <h1 className="font-serif text-[clamp(2.75rem,10vw,8rem)] leading-[0.82] tracking-[-0.05em] text-[var(--text-primary)] break-words">
                  Критическая
                  <br />
                  <span className="italic text-[var(--accent-red)]">ошибка</span>
                  <span className="text-[var(--text-primary)]">.</span>
                </h1>
              </motion.div>

              {/* Правая колонка — описание и кнопка */}
              <motion.div
                className="lg:col-span-5 min-w-0"
                initial={prefersReduced ? false : { opacity: 0, y: 24 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 1, delay: 0.15, ease: EASE_OUT }}
              >
                <div className="inline-flex items-center gap-2 mb-6">
                  <ExclamationTriangleIcon className="w-3.5 h-3.5 text-[var(--accent-red)]" />
                  <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--accent-red)]">
                    System error
                  </span>
                </div>

                <p className="font-serif text-2xl sm:text-3xl leading-[1.15] tracking-[-0.01em] text-[var(--text-primary)] mb-6">
                  Произошла непредвиденная ошибка.
                </p>

                <p className="text-base text-[var(--text-secondary)] leading-relaxed mb-10">
                  Попробуйте обновить страницу.
                </p>

                {error.digest && (
                  <p className="mb-8 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)]">
                    digest · {error.digest}
                  </p>
                )}

                <button
                  onClick={reset}
                  className="group inline-flex items-center gap-4 pl-0 pr-2 py-3 border-y-2 border-[var(--text-primary)] text-[var(--text-primary)] hover:bg-[var(--text-primary)] hover:text-[var(--bg-primary)] transition-colors duration-500"
                >
                  <span className="font-mono text-[11px] uppercase tracking-[0.25em]">
                    Обновить страницу
                  </span>
                  <ArrowRightIcon
                    className="w-4 h-4 transition-transform duration-500 group-hover:translate-x-1"
                    aria-hidden="true"
                  />
                </button>
              </motion.div>
            </div>
          </div>
        </main>

        {/* ============ FOOTER — тонкая полоса ============ */}
        <motion.div
          className="border-t border-[var(--line)]"
          initial={prefersReduced ? false : { opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.8, delay: 0.5, ease: EASE_EDITORIAL }}
        >
          <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-10 lg:py-14">
            <div className="grid lg:grid-cols-12 gap-6 items-baseline">
              <div className="lg:col-span-8">
                <p className="font-serif text-lg sm:text-xl italic text-[var(--text-secondary)] leading-relaxed">
                  Если ошибка повторяется, попробуйте позже — мы уже разбираемся.
                </p>
              </div>
              <div className="lg:col-span-4 lg:text-right">
                <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                  MovieTracker · {new Date().getFullYear()}
                </p>
              </div>
            </div>
          </div>
        </motion.div>
      </body>
    </html>
  );
}