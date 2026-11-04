'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { motion, useReducedMotion } from 'framer-motion';
import { mediaApi, Media } from '@/lib/api/media';
import {
  ClipboardDocumentListIcon,
  ListBulletIcon,
  SparklesIcon,
  ShieldCheckIcon,
  ArrowRightIcon,
  ArrowUpRightIcon,
  PlusCircleIcon,
  FilmIcon,
} from '@heroicons/react/24/outline';

// ---------- Стабильные данные ----------

const FEATURES = [
  {
    number: '01',
    icon: ClipboardDocumentListIcon,
    title: 'Отметки',
    description: 'Отмечайте просмотренные фильмы, ставьте оценки и пишите рецензии',
  },
  {
    number: '02',
    icon: ListBulletIcon,
    title: 'Списки',
    description: 'Создавайте тематические подборки и делитесь ими с друзьями',
  },
  {
    number: '03',
    icon: SparklesIcon,
    title: 'Рандомайзер',
    description: 'Не знаете, что посмотреть? Мы подберём случайный фильм',
  },
  {
    number: '04',
    icon: ShieldCheckIcon,
    title: 'Модерация',
    description: 'Предлагайте новые фильмы и помогайте развивать каталог',
  },
];

const STATS = [
  { value: '1 000+', label: 'фильмов в каталоге' },
  { value: '500+', label: 'активных кинолюбителей' },
  { value: '2 000+', label: 'создано списков' },
  { value: '10 000+', label: 'поставлено оценок' },
];

const HERO_POSTERS = [
  { tint: 'var(--accent-purple)', rotate: -14, top: '4%', left: '4%', z: 1 },
  { tint: 'var(--accent-green)', rotate: 9, top: '12%', left: '36%', z: 2 },
  { tint: 'var(--accent-yellow)', rotate: -5, top: '0%', left: '64%', z: 3 },
  { tint: 'var(--accent-red)', rotate: 12, top: '36%', left: '18%', z: 4 },
  { tint: 'var(--accent-yellow)', rotate: -8, top: '42%', left: '50%', z: 5 },
];

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const EASE_EDITORIAL = [0.76, 0, 0.24, 1] as const;

export default function HomePage() {
  const prefersReduced = useReducedMotion();
  const [popularMedia, setPopularMedia] = useState<Media[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const response = await mediaApi.getList({ per_page: 6 });
        if (!cancelled) setPopularMedia(response.data || []);
      } catch (error) {
        console.error('Ошибка загрузки медиа:', error);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const fadeUp = prefersReduced
    ? {}
    : {
        initial: { opacity: 0, y: 30 },
        whileInView: { opacity: 1, y: 0 },
        viewport: { once: true, margin: '-100px' },
      };

  const [statCatalog, statUsers, statLists, statRatings] = STATS;

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      {/* ============ HERO ============ */}
      <section className="relative overflow-hidden bg-[var(--bg-primary)]">
        <div
          aria-hidden
          className="pointer-events-none absolute -top-32 right-0 w-[600px] h-[600px] rounded-full blur-[140px] opacity-20"
          style={{
            background: 'radial-gradient(circle, var(--accent-yellow), transparent 70%)',
          }}
        />

        {/* Верхняя редакционная полоса */}
        <div className="relative max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center justify-between border-b border-[var(--line)] pb-5">
            <span className="font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
              MovieTracker — Кинодневник
            </span>
            <span className="hidden sm:flex items-center gap-3 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
              <span>Est. 2024</span>
              <span className="w-1 h-1 rounded-full bg-[var(--accent-yellow)]" />
              <span>Бесплатно</span>
            </span>
          </div>
        </div>

        {/* Тело hero */}
        <div className="relative max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-20 lg:pb-28">
          <div className="grid lg:grid-cols-12 gap-12 lg:gap-8 items-center">
            {/* Левая колонка */}
            <motion.div
              className="lg:col-span-7 relative z-10"
              initial={prefersReduced ? false : { opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 1, ease: EASE_OUT }}
            >
              <div className="flex items-center gap-3 mb-8">
                <span className="h-px w-10 bg-[var(--text-primary)]" />
                <span className="font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-secondary)]">
                  Добро пожаловать в MovieTracker
                </span>
              </div>

              <h1 className="font-serif text-[clamp(3rem,12vw,10rem)] leading-[0.84] tracking-[-0.035em] text-[var(--text-primary)]">
                Ваш личный
                <br />
                <span className="relative inline-block">
                  <span className="relative z-10 italic">кинодневник</span>
                  <span
                    aria-hidden
                    className="absolute left-0 right-0 bottom-[0.07em] h-[0.1em] bg-[var(--accent-yellow)] -rotate-1"
                  />
                </span>
              </h1>

              <p className="mt-8 max-w-md text-base sm:text-lg text-[var(--text-secondary)] leading-relaxed">
                Отслеживайте просмотры, собирайте списки, делитесь с друзьями
                и открывайте новое кино — без лишнего шума.
              </p>

              <div className="mt-10 flex flex-col sm:flex-row sm:items-center gap-5 sm:gap-10">
                <Link href="/entries" className="group inline-flex items-center gap-3">
                  <span className="w-11 h-11 rounded-full bg-[var(--text-primary)] text-[var(--bg-primary)] grid place-items-center transition-transform duration-500 group-hover:rotate-[-8deg] group-hover:scale-105">
                    <ClipboardDocumentListIcon className="w-5 h-5" />
                  </span>
                  <span className="font-mono text-[11px] uppercase tracking-[0.2em] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
                    Мои отметки
                  </span>
                </Link>
                <Link href="/random" className="group inline-flex items-center gap-3">
                  <span className="w-11 h-11 rounded-full border border-[var(--line)] grid place-items-center transition-colors duration-300 group-hover:border-[var(--text-primary)]">
                    <SparklesIcon className="w-5 h-5" />
                  </span>
                  <span className="font-mono text-[11px] uppercase tracking-[0.2em] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
                    Случайный фильм
                  </span>
                </Link>
              </div>
            </motion.div>

            {/* Правая колонка: веер постеров */}
            <div className="hidden lg:block lg:col-span-5 relative h-[520px]">
              {HERO_POSTERS.map((p, i) => (
                <motion.div
                  key={i}
                  className="absolute w-36 xl:w-40 aspect-[2/3] rounded-[3px] overflow-hidden border border-white/10 shadow-[0_30px_60px_-30px_rgba(0,0,0,0.7)] cursor-pointer"
                  style={{
                    top: p.top,
                    left: p.left,
                    zIndex: p.z,
                    background: `linear-gradient(160deg, ${p.tint}22, ${p.tint}bb)`,
                  }}
                  initial={prefersReduced ? false : { opacity: 0, y: 40, rotate: p.rotate - 8 }}
                  animate={{ opacity: 1, y: 0, rotate: p.rotate }}
                  transition={{ duration: 1.1, delay: 0.25 + i * 0.1, ease: EASE_OUT }}
                  whileHover={
                    prefersReduced
                      ? undefined
                      : {
                          y: -14,
                          rotate: p.rotate * 0.4,
                          scale: 1.03,
                          zIndex: 30,
                          transition: { duration: 0.6, ease: EASE_EDITORIAL },
                        }
                  }
                >
                  <div className="w-full h-full grid place-items-center">
                    <FilmIcon className="w-8 h-8 text-black/25" />
                  </div>
                  <div
                    className="absolute inset-0 opacity-25 mix-blend-overlay"
                    style={{
                      backgroundImage:
                        'repeating-linear-gradient(45deg, rgba(255,255,255,0.15) 0 1px, transparent 1px 4px)',
                    }}
                  />
                </motion.div>
              ))}
            </div>
          </div>

          {/* Линия доверия */}
          <div className="mt-20 lg:mt-28 pt-6 border-t border-[var(--line)] flex items-center gap-3 text-xs sm:text-sm text-[var(--text-muted)]">
            <div className="flex -space-x-2">
              {['#f4c44a', '#7aa84a', '#8a7ac4', '#d45a4a'].map((c, i) => (
                <span
                  key={i}
                  className="w-6 h-6 rounded-full border-2 border-[var(--bg-primary)]"
                  style={{ background: c }}
                />
              ))}
            </div>
            <span>Уже 500+ кинолюбителей ведут дневник</span>
          </div>
        </div>
      </section>

      {/* ============ FEATURES ============ */}
      <section className="bg-[var(--bg-primary)] border-t border-[var(--line)] py-24 lg:py-32">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10">
          <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-8 mb-16 lg:mb-20">
            <div>
              <p className="font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-5">
                Возможности
              </p>
              <h2 className="font-serif text-4xl sm:text-5xl lg:text-6xl leading-[0.92] tracking-[-0.025em] max-w-2xl">
                Всё, что нужно настоящему киноману
              </h2>
            </div>
            <Link
              href="/features"
              className="group inline-flex items-center gap-3 shrink-0 self-start sm:self-end"
            >
              <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
                Узнать подробнее
              </span>
              <span className="w-10 h-10 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
                <ArrowRightIcon className="w-4 h-4 transition-transform duration-500 group-hover:translate-x-0.5" />
              </span>
            </Link>
          </div>

          <div className="border-t border-[var(--line)]">
            {FEATURES.map((f, i) => {
              const Icon = f.icon;
              return (
                <motion.div
                  key={f.title}
                  className="group relative border-b border-[var(--line)]"
                  {...fadeUp}
                  transition={{ duration: 0.7, delay: i * 0.08, ease: EASE_OUT }}
                >
                  <div className="grid grid-cols-12 gap-4 sm:gap-6 py-8 lg:py-10 items-start lg:items-center">
                    <div className="col-span-2 sm:col-span-1">
                      <span className="font-mono text-[11px] text-[var(--text-muted)] group-hover:text-[var(--accent-yellow)] transition-colors">
                        {f.number}
                      </span>
                    </div>
                    <div className="col-span-10 sm:col-span-4 flex items-center gap-3">
                      <Icon className="w-5 h-5 text-[var(--text-muted)] group-hover:text-[var(--text-primary)] transition-colors" />
                      <h3 className="font-serif text-2xl lg:text-3xl tracking-[-0.01em]">
                        {f.title}
                      </h3>
                    </div>
                    <div className="col-span-12 sm:col-span-5 lg:col-span-5 mt-3 sm:mt-0">
                      <p className="text-sm lg:text-base text-[var(--text-secondary)] leading-relaxed">
                        {f.description}
                      </p>
                    </div>
                    <div className="hidden lg:flex lg:col-span-2 justify-end">
                      <span className="w-9 h-9 rounded-full border border-[var(--line)] grid place-items-center opacity-0 -translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all duration-500 group-hover:border-[var(--text-primary)]">
                        <ArrowUpRightIcon className="w-4 h-4" />
                      </span>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ============ STATS (вплетены в повествование) ============ */}
      <section className="bg-[var(--bg-secondary)] border-y border-[var(--line)] py-24 lg:py-32">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 grid lg:grid-cols-12 gap-10 lg:gap-8">
          <div className="lg:col-span-3">
            <p className="font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)] lg:sticky lg:top-24">
              Сообщество
            </p>
          </div>
          <div className="lg:col-span-9">
            <motion.h2
              {...fadeUp}
              transition={{ duration: 0.8, ease: EASE_OUT }}
              className="font-serif text-4xl sm:text-5xl lg:text-6xl leading-[0.95] tracking-[-0.025em]"
            >
              Растём каждый день —
              <br />
              вместе с вами
            </motion.h2>

            <motion.p
              {...fadeUp}
              transition={{ duration: 0.8, delay: 0.1, ease: EASE_OUT }}
              className="mt-10 max-w-3xl font-serif text-2xl sm:text-3xl lg:text-4xl leading-[1.25] tracking-[-0.01em] text-[var(--text-primary)]"
            >
              Сегодня в каталоге{' '}
              <span className="font-sans font-semibold text-[var(--accent-yellow)]">
                {statCatalog.value}
              </span>{' '}
              {statCatalog.label}, а{' '}
              <span className="font-sans font-semibold text-[var(--accent-yellow)]">
                {statUsers.value}
              </span>{' '}
              {statUsers.label} уже ведут здесь свой дневник. Вместе вы создали{' '}
              <span className="font-sans font-semibold text-[var(--accent-yellow)]">
                {statLists.value}
              </span>{' '}
              {statLists.label} и поставили{' '}
              <span className="font-sans font-semibold text-[var(--accent-yellow)]">
                {statRatings.value}
              </span>{' '}
              {statRatings.label} — и это только начало.
            </motion.p>

            <motion.p
              {...fadeUp}
              transition={{ duration: 0.8, delay: 0.2, ease: EASE_OUT }}
              className="mt-10 max-w-xl text-sm sm:text-base text-[var(--text-muted)] leading-relaxed"
            >
              MovieTracker — это не просто трекер. Это сообщество людей, которые любят кино
              и хотят помнить, что уже посмотрели.
            </motion.p>
          </div>
        </div>
      </section>

      {/* ============ POPULAR ============ */}
      <section className="bg-[var(--bg-primary)] border-t border-[var(--line)] py-24 lg:py-32">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10">
          <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-8 mb-14 lg:mb-20">
            <div>
              <p className="font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-5">
                Каталог
              </p>
              <h2 className="font-serif text-4xl sm:text-5xl lg:text-6xl leading-[0.92] tracking-[-0.025em]">
                Популярное сейчас
              </h2>
            </div>
            <Link
              href="/catalog"
              className="group inline-flex items-center gap-3 shrink-0 self-start sm:self-end"
            >
              <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
                Весь каталог
              </span>
              <span className="w-10 h-10 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
                <ArrowRightIcon className="w-4 h-4 transition-transform duration-500 group-hover:translate-x-0.5" />
              </span>
            </Link>
          </div>

          {loading ? (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 lg:gap-5 items-start">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className={i % 2 === 1 ? 'lg:mt-12' : ''}>
                  <div className="aspect-[2/3] rounded-[2px] bg-[var(--bg-tertiary)] animate-pulse" />
                  <div className="mt-4 h-3 w-3/4 rounded bg-[var(--bg-tertiary)] animate-pulse" />
                  <div className="mt-2 h-2 w-1/3 rounded bg-[var(--bg-tertiary)] animate-pulse" />
                </div>
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 lg:gap-5 items-start">
              {popularMedia.map((media, index) => (
                <motion.div
                  key={media.id}
                  {...fadeUp}
                  transition={{ duration: 0.7, delay: index * 0.06, ease: EASE_OUT }}
                  className={index % 2 === 1 ? 'lg:mt-12' : ''}
                >
                  <Link href={`/media/${media.id}`} className="group block">
                    <div className="relative aspect-[2/3] overflow-hidden rounded-[2px] bg-[var(--bg-tertiary)]">
                      {media.poster_url ? (
                        <img
                          src={media.poster_url}
                          alt={media.title_ru}
                          loading="lazy"
                          className="w-full h-full object-cover transition-transform duration-[1400ms] ease-[cubic-bezier(0.76,0,0.24,1)] group-hover:scale-[1.08]"
                        />
                      ) : (
                        <div className="w-full h-full grid place-items-center text-[var(--text-muted)]">
                          <FilmIcon className="w-10 h-10 opacity-30" />
                        </div>
                      )}

                      {/* Градиент на hover */}
                      <span className="pointer-events-none absolute inset-0 bg-gradient-to-t from-black/80 via-black/0 to-black/0 opacity-0 group-hover:opacity-100 transition-opacity duration-700" />

                      {/* Тонкая золотая рамка */}
                      <span className="pointer-events-none absolute inset-2 border border-transparent group-hover:border-[var(--accent-yellow)]/60 transition-colors duration-700" />
                    </div>
                    <div className="mt-4">
                      <h3 className="font-serif text-base lg:text-lg leading-snug line-clamp-2 group-hover:italic transition-[font-style] duration-300">
                        {media.title_ru}
                      </h3>
                      {media.release_date && (
                        <p className="mt-1.5 text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">
                          {new Date(media.release_date).getFullYear()}
                        </p>
                      )}
                    </div>
                  </Link>
                </motion.div>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* ============ CTA ============ */}
      <section className="relative overflow-hidden bg-[var(--accent-yellow)] py-24 lg:py-32">
        <div
          aria-hidden
          className="absolute inset-0 opacity-[0.05]"
          style={{
            backgroundImage:
              'repeating-linear-gradient(90deg, #000 0 1px, transparent 1px 12px)',
          }}
        />
        <div className="relative max-w-[1400px] mx-auto px-6 lg:px-10">
          <div className="grid lg:grid-cols-12 gap-10 lg:gap-8 items-end">
            <motion.div
              className="lg:col-span-8"
              {...fadeUp}
              transition={{ duration: 0.8, ease: EASE_OUT }}
            >
              <p className="font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-black/60 mb-6">
                Начните сегодня
              </p>
              <h2 className="font-serif text-5xl sm:text-6xl lg:text-8xl leading-[0.88] tracking-[-0.035em] text-black">
                Заведите свой
                <br />
                кинодневник за минуту
              </h2>
            </motion.div>

            <motion.div
              className="lg:col-span-4 lg:text-right"
              {...fadeUp}
              transition={{ duration: 0.8, delay: 0.1, ease: EASE_OUT }}
            >
              <p className="text-lg sm:text-xl text-black/70 max-w-xs lg:ml-auto">
                Бесплатно. Без рекламы. Только вы и кино.
              </p>
              <Link href="/register" className="group inline-flex items-center gap-4 mt-8">
                <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-black border-b border-black/40 group-hover:border-black pb-1 transition-colors">
                  Создать аккаунт
                </span>
                <span className="w-12 h-12 rounded-full bg-black text-[var(--accent-yellow)] grid place-items-center transition-transform duration-500 group-hover:scale-110 group-hover:rotate-6">
                  <PlusCircleIcon className="w-5 h-5" />
                </span>
              </Link>
            </motion.div>
          </div>
        </div>
      </section>
    </div>
  );
}