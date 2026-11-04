// frontend/app/not-found.tsx
'use client';

import Link from 'next/link';
import { motion, useReducedMotion } from 'framer-motion';
import { ArrowRightIcon, ArrowUpRightIcon } from '@heroicons/react/24/outline';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const EASE_EDITORIAL = [0.76, 0, 0.24, 1] as const;

export default function NotFound() {
  const prefersReduced = useReducedMotion();

  const fadeUp = prefersReduced
    ? {}
    : {
        initial: { opacity: 0, y: 24 },
        animate: { opacity: 1, y: 0 },
      };

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      {/* ============ MASTHEAD ============ */}
      <section className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
            <Link
              href="/"
              className="group inline-flex items-center gap-2 hover:text-[var(--text-primary)] transition-colors"
            >
              <span>MovieTracker</span>
            </Link>
            <span className="hidden sm:inline">Ошибка · 404</span>
          </div>
        </div>
      </section>

      {/* ============ HERO — экспериментальная типографика ============ */}
      <section className="relative overflow-hidden">
        {/* Едва заметная «сетка» */}
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
            {/* Левая колонка — гигантский «404» с editorial-подачей */}
            <motion.div
              className="lg:col-span-7 min-w-0"
              {...fadeUp}
              transition={{ duration: 1, ease: EASE_OUT }}
            >
              <div className="flex items-center gap-3 mb-8">
                <span className="h-px w-10 bg-[var(--text-primary)]" />
                <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-secondary)]">
                  Страница не найдена
                </span>
              </div>

              <h1 className="font-serif leading-[0.78] tracking-[-0.06em] text-[var(--text-primary)] select-none">
                <span className="block text-[clamp(8rem,32vw,28rem)]">
                  4<span className="italic text-[var(--accent-yellow)]">0</span>4
                </span>
              </h1>
            </motion.div>

            {/* Правая колонка — описание и CTA */}
            <motion.div
              className="lg:col-span-5 min-w-0"
              {...fadeUp}
              transition={{ duration: 1, delay: 0.15, ease: EASE_OUT }}
            >
              <p className="font-serif text-2xl sm:text-3xl leading-[1.15] tracking-[-0.01em] text-[var(--text-primary)] mb-8">
                Возможно, она была удалена, перемещена или вы ввели
                неверный адрес.
              </p>

              <p className="text-base text-[var(--text-secondary)] leading-relaxed mb-12">
                Не волнуйтесь, мы поможем вам найти то, что нужно.
              </p>

              <div className="space-y-1">
                <Link
                  href="/catalog"
                  className="group flex items-center justify-between gap-4 py-5 border-t border-[var(--line)] hover:border-[var(--text-primary)] transition-colors duration-500"
                >
                  <span className="flex items-baseline gap-4 min-w-0">
                    <span className="font-mono text-[10px] tracking-[0.2em] text-[var(--text-muted)] tabular-nums shrink-0">
                      01
                    </span>
                    <span className="font-serif text-xl sm:text-2xl text-[var(--text-primary)] group-hover:italic transition-[font-style] duration-300">
                      В каталог
                    </span>
                  </span>
                  <ArrowUpRightIcon
                    className="w-4 h-4 shrink-0 text-[var(--text-muted)] transition-all duration-500 group-hover:text-[var(--text-primary)] group-hover:rotate-45"
                    aria-hidden="true"
                  />
                </Link>

                <Link
                  href="/"
                  className="group flex items-center justify-between gap-4 py-5 border-t border-[var(--line)] hover:border-[var(--text-primary)] transition-colors duration-500"
                >
                  <span className="flex items-baseline gap-4 min-w-0">
                    <span className="font-mono text-[10px] tracking-[0.2em] text-[var(--text-muted)] tabular-nums shrink-0">
                      02
                    </span>
                    <span className="font-serif text-xl sm:text-2xl text-[var(--text-primary)] group-hover:italic transition-[font-style] duration-300">
                      На главную
                    </span>
                  </span>
                  <ArrowRightIcon
                    className="w-4 h-4 shrink-0 text-[var(--text-muted)] transition-all duration-500 group-hover:text-[var(--text-primary)] group-hover:translate-x-0.5"
                    aria-hidden="true"
                  />
                </Link>
              </div>
            </motion.div>
          </div>
        </div>
      </section>
      <motion.section
        className="border-t border-[var(--line)]"
        initial={prefersReduced ? false : { opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.8, delay: 0.5, ease: EASE_EDITORIAL }}
      >
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-10 lg:py-14">
          <div className="grid lg:grid-cols-12 gap-6 items-baseline">
            <div className="lg:col-span-8">
              <p className="font-serif text-lg sm:text-xl italic text-[var(--text-secondary)] leading-relaxed">
                Если вы считаете, что это ошибка, свяжитесь с поддержкой
              </p>
            </div>
            <div className="lg:col-span-4 lg:text-right">
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                MovieTracker · {new Date().getFullYear()}
              </p>
            </div>
          </div>
        </div>
      </motion.section>
    </div>
  );
}