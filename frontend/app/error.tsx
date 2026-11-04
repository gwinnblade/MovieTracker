// frontend/app/error.tsx
'use client';

import { useEffect } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import {
  ArrowRightIcon,
  ArrowPathIcon,
  HomeIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const EASE_EDITORIAL = [0.76, 0, 0.24, 1] as const;

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const prefersReduced = useReducedMotion();
  const isNotFound = error.message?.includes('404');

  useEffect(() => {
    console.error('Error occurred:', error);
  }, [error]);

  const accent = isNotFound ? 'var(--accent-yellow)' : 'var(--accent-red)';
  const code = isNotFound ? '404' : '500';
  const title = isNotFound ? 'Страница не найдена' : 'Что-то пошло не так';
  const description = isNotFound
    ? 'К сожалению, запрашиваемая страница не существует.'
    : 'Произошла непредвиденная ошибка. Не волнуйтесь, мы уже работаем над этим!';
  const tag = isNotFound ? 'Not found' : 'Ошибка';

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      {/* ============ MASTHEAD ============ */}
      <section className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
            <a
              href="/"
              className="group inline-flex items-center gap-2 hover:text-[var(--text-primary)] transition-colors"
            >
              <span>MovieTracker</span>
            </a>
            <span className="hidden sm:inline">{tag}</span>
          </div>
        </div>
      </section>

      {/* ============ HERO ============ */}
      <section className="relative overflow-hidden">
        {/* Тонкая «сетка» — редакционный фон */}
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
            {/* Левая колонка — гигантский код */}
            <motion.div
              className="lg:col-span-7 min-w-0"
              initial={prefersReduced ? false : { opacity: 0, y: 24 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 1, ease: EASE_OUT }}
            >
              <div className="flex items-center gap-3 mb-8">
                <span className="h-px w-10 bg-[var(--text-primary)]" />
                <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-secondary)]">
                  {tag}
                </span>
              </div>

              <h1 className="font-serif leading-[0.78] tracking-[-0.06em] text-[var(--text-primary)] select-none">
                <span className="block text-[clamp(6rem,26vw,24rem)]">
                  {isNotFound ? (
                    <>
                      4<span className="italic" style={{ color: accent }}>0</span>4
                    </>
                  ) : (
                    <>
                      5<span className="italic" style={{ color: accent }}>0</span>0
                    </>
                  )}
                </span>
              </h1>
            </motion.div>

            {/* Правая колонка — заголовок, текст, действия */}
            <motion.div
              className="lg:col-span-5 min-w-0"
              initial={prefersReduced ? false : { opacity: 0, y: 24 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 1, delay: 0.15, ease: EASE_OUT }}
            >
              <div className="inline-flex items-center gap-2 mb-6">
                <ExclamationTriangleIcon
                  className="w-3.5 h-3.5"
                  style={{ color: accent }}
                  aria-hidden="true"
                />
                <span
                  className="font-mono text-[10px] uppercase tracking-[0.2em]"
                  style={{ color: accent }}
                >
                  {isNotFound ? 'Страница не существует' : 'Внутренняя ошибка'}
                </span>
              </div>

              <p className="font-serif text-2xl sm:text-3xl leading-[1.15] tracking-[-0.01em] text-[var(--text-primary)] mb-6">
                {title}
              </p>

              <p className="text-base text-[var(--text-secondary)] leading-relaxed mb-10">
                {description}
              </p>

              {/* Действия — редакционный индекс */}
              <div className="space-y-1">
                {!isNotFound && (
                  <button
                    onClick={reset}
                    className="group flex w-full items-center justify-between gap-4 py-5 border-t border-[var(--line)] hover:border-[var(--text-primary)] transition-colors duration-500 text-left"
                  >
                    <span className="flex items-baseline gap-4 min-w-0">
                      <span className="font-mono text-[10px] tracking-[0.2em] text-[var(--text-muted)] tabular-nums shrink-0">
                        01
                      </span>
                      <span className="font-serif text-xl sm:text-2xl text-[var(--text-primary)] group-hover:italic transition-[font-style] duration-300">
                        Попробовать снова
                      </span>
                    </span>
                    <ArrowPathIcon
                      className="w-4 h-4 shrink-0 text-[var(--text-muted)] transition-all duration-500 group-hover:text-[var(--text-primary)] group-hover:rotate-180"
                      aria-hidden="true"
                    />
                  </button>
                )}

                <a
                  href="/"
                  className="group flex items-center justify-between gap-4 py-5 border-t border-[var(--line)] hover:border-[var(--text-primary)] transition-colors duration-500"
                >
                  <span className="flex items-baseline gap-4 min-w-0">
                    <span className="font-mono text-[10px] tracking-[0.2em] text-[var(--text-muted)] tabular-nums shrink-0">
                      {isNotFound ? '01' : '02'}
                    </span>
                    <span className="font-serif text-xl sm:text-2xl text-[var(--text-primary)] group-hover:italic transition-[font-style] duration-300">
                      На главную
                    </span>
                  </span>
                  <HomeIcon
                    className="w-4 h-4 shrink-0 text-[var(--text-muted)] transition-all duration-500 group-hover:text-[var(--text-primary)] group-hover:translate-x-0.5"
                    aria-hidden="true"
                  />
                </a>
              </div>

              {!isNotFound && (
                <a
                  href="/catalog"
                  className="mt-6 inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] hover:text-[var(--text-primary)] border-b border-transparent hover:border-[var(--text-primary)] pb-0.5 transition-colors"
                >
                  Или открыть каталог
                  <ArrowRightIcon className="w-3.5 h-3.5" aria-hidden="true" />
                </a>
              )}
            </motion.div>
          </div>
        </div>
      </section>

      {/* ============ ТЕХНИЧЕСКАЯ ИНФО (только в dev) ============ */}
      {process.env.NODE_ENV === 'development' && (
        <motion.section
          className="border-t border-[var(--line)] bg-[var(--bg-secondary)]"
          initial={prefersReduced ? false : { opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.8, delay: 0.4, ease: EASE_EDITORIAL }}
        >
          <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-10 lg:py-14">
            <div className="grid lg:grid-cols-12 gap-6">
              <div className="lg:col-span-3">
                <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                  Technical details
                </p>
              </div>
              <div className="lg:col-span-9 space-y-4">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)] mb-2">
                    message
                  </p>
                  <p className="font-mono text-xs text-[var(--text-secondary)] break-all leading-relaxed">
                    {error.message || 'Unknown error'}
                  </p>
                </div>
                {error.digest && (
                  <div className="pt-4 border-t border-[var(--line)]">
                    <p className="font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)] mb-2">
                      digest
                    </p>
                    <p className="font-mono text-xs text-[var(--text-secondary)] break-all leading-relaxed">
                      {error.digest}
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </motion.section>
      )}
    </div>
  );
}