'use client';

import { useParams } from 'next/navigation';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import { motion, useReducedMotion } from 'framer-motion';
import { personApi, Person } from '@/lib/api/media';
import { resolveMediaUrl } from '@/lib/utils/media-url';
import {
  UserIcon,
  FilmIcon,
  ChevronLeftIcon,
  ArrowRightIcon,
  ArrowUpRightIcon,
  ExclamationTriangleIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

type LoadState = 'loading' | 'ready' | 'notfound' | 'error';

const STAGGER = ['', 'lg:mt-16', 'lg:mt-4', 'lg:mt-24', 'lg:mt-8'];

function plural(n: number, one: string, few: string, many: string) {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return one;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return few;
  return many;
}

export default function PersonPage() {
  const params = useParams();
  const prefersReduced = useReducedMotion();
  const id = Number(params?.id);

  const [person, setPerson] = useState<Person | null>(null);
  const [state, setState] = useState<LoadState>('loading');

  useEffect(() => {
    if (!id) {
      setState('notfound');
      return;
    }

    (async () => {
      setState('loading');
      try {
        const data = await personApi.getById(id);
        setPerson(data);
        setState('ready');
      } catch (error: any) {
        setState(error?.response?.status === 404 ? 'notfound' : 'error');
      }
    })();
  }, [id]);

  if (state === 'loading') return <PersonSkeleton />;
  if (state === 'notfound') return <NotFoundState />;
  if (state === 'error') return <ErrorState onRetry={() => window.location.reload()} />;
  if (!person) return <NotFoundState />;

  const directedMovies = person.filmography.filter(
    (f) => f.pivot.role_name_ru === 'Режиссер'
  );
  const actedMovies = person.filmography.filter((f) => f.pivot.role_name_ru === 'Актер');
  const totalWorks = person.filmography.length;

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      {/* ============ MASTHEAD ============ */}
      <section className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <nav
            aria-label="Хлебные крошки"
            className="flex items-center gap-3 pb-5 border-b border-[var(--line)] font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)] overflow-hidden"
          >
            <Link
              href="/catalog"
              className="group inline-flex items-center gap-2 hover:text-[var(--text-primary)] transition-colors shrink-0"
            >
              <ChevronLeftIcon className="w-3.5 h-3.5 transition-transform group-hover:-translate-x-0.5" />
              <span>Каталог</span>
            </Link>
            <span className="text-[var(--text-muted)]/50 shrink-0">/</span>
            <span className="text-[var(--text-secondary)] truncate min-w-0">
              {person.name}
            </span>
          </nav>
        </div>

        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-14 lg:pb-20">
          <div className="grid lg:grid-cols-12 gap-10 items-end">
            <motion.div
              className="lg:col-span-9 min-w-0"
              initial={prefersReduced ? false : { opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.9, ease: EASE_OUT }}
            >
              <div className="flex items-center gap-3 mb-6">
                <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-yellow)]" />
                <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-secondary)]">
                  Кинодеятель
                </span>
              </div>

              <h1 className="font-serif text-[clamp(2.75rem,11vw,9.5rem)] leading-[0.82] tracking-[-0.045em] break-words">
                {person.name}
                <span className="text-[var(--accent-yellow)]">.</span>
              </h1>
            </motion.div>

            <motion.div
              className="lg:col-span-3 lg:text-right"
              initial={prefersReduced ? false : { opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.9, delay: 0.1, ease: EASE_OUT }}
            >
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-3">
                Фильмография
              </p>
              <p className="font-serif text-4xl sm:text-5xl tabular-nums tracking-[-0.03em]">
                {String(totalWorks).padStart(2, '0')}
              </p>
              <p className="mt-1 text-xs text-[var(--text-muted)]">
                {plural(totalWorks, 'работа', 'работы', 'работ')} в базе
              </p>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ============ РЕЖИССЁРСКИЕ РАБОТЫ ============ */}
      {directedMovies.length > 0 && (
        <section className="border-t border-[var(--line)]">
          <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
            <div className="grid lg:grid-cols-12 gap-10 lg:gap-14">
              <motion.div
                className="lg:col-span-3"
                initial={prefersReduced ? false : { opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: '-80px' }}
                transition={{ duration: 0.7, ease: EASE_OUT }}
              >
                <div className="lg:sticky lg:top-24">
                  <div className="flex items-center gap-2 mb-4">
                    <FilmIcon className="w-3.5 h-3.5 text-[var(--accent-yellow)]" />
                    <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                      Как режиссёр
                    </p>
                  </div>
                  <h2 className="font-serif text-3xl sm:text-4xl leading-[0.95] tracking-[-0.02em]">
                    Режиссёрские
                    <br />
                    <span className="italic">работы</span>
                  </h2>
                  <p className="mt-4 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                    {directedMovies.length}{' '}
                    {plural(directedMovies.length, 'фильм', 'фильма', 'фильмов')}
                  </p>
                </div>
              </motion.div>

              <div className="lg:col-span-9">
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 lg:gap-x-5 lg:gap-y-0 items-start">
                  {directedMovies.map((movie, i) => (
                    <motion.div
                      key={movie.id}
                      initial={prefersReduced ? false : { opacity: 0, y: 14 }}
                      whileInView={{ opacity: 1, y: 0 }}
                      viewport={{ once: true, margin: '-60px' }}
                      transition={{
                        duration: 0.6,
                        delay: Math.min(i * 0.05, 0.4),
                        ease: EASE_OUT,
                      }}
                      className={STAGGER[i % 4]}
                    >
                      <MovieCard movie={movie} />
                    </motion.div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* ============ АКТЁРСКИЕ РАБОТЫ ============ */}
      {actedMovies.length > 0 && (
        <section className="border-t border-[var(--line)] bg-[var(--bg-secondary)]">
          <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
            <div className="grid lg:grid-cols-12 gap-10 lg:gap-14">
              <motion.div
                className="lg:col-span-3"
                initial={prefersReduced ? false : { opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: '-80px' }}
                transition={{ duration: 0.7, ease: EASE_OUT }}
              >
                <div className="lg:sticky lg:top-24">
                  <div className="flex items-center gap-2 mb-4">
                    <UserIcon className="w-3.5 h-3.5 text-[var(--accent-yellow)]" />
                    <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                      Как актёр
                    </p>
                  </div>
                  <h2 className="font-serif text-3xl sm:text-4xl leading-[0.95] tracking-[-0.02em]">
                    Фильмы
                    <br />
                    <span className="italic">с участием</span>
                  </h2>
                  <p className="mt-4 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                    {actedMovies.length}{' '}
                    {plural(actedMovies.length, 'фильм', 'фильма', 'фильмов')}
                  </p>
                </div>
              </motion.div>

              <div className="lg:col-span-9">
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 lg:gap-x-5 lg:gap-y-0 items-start">
                  {actedMovies.map((movie, i) => (
                    <motion.div
                      key={movie.id}
                      initial={prefersReduced ? false : { opacity: 0, y: 14 }}
                      whileInView={{ opacity: 1, y: 0 }}
                      viewport={{ once: true, margin: '-60px' }}
                      transition={{
                        duration: 0.6,
                        delay: Math.min(i * 0.05, 0.4),
                        ease: EASE_OUT,
                      }}
                      className={STAGGER[i % 4]}
                    >
                      <MovieCard movie={movie} />
                    </motion.div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* ============ ПУСТО ============ */}
      {person.filmography.length === 0 && (
        <section className="max-w-[1400px] mx-auto px-6 lg:px-10 py-24 lg:py-32">
          <div className="py-20 text-center border-y border-[var(--line)]">
            <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
              Пусто
            </p>
            <h2 className="font-serif text-4xl sm:text-5xl tracking-[-0.02em] mb-4">
              Фильмография пока пуста
            </h2>
            <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
              Мы ещё не добавили ни одной работы этого кинодеятеля в каталог.
            </p>
          </div>
        </section>
      )}
    </div>
  );
}

/* ---------- Компонент карточки фильма ---------- */

function MovieCard({ movie }: { movie: Person['filmography'][0] }) {
  return (
    <Link href={`/media/${movie.id}`} className="group block">
      <div className="relative aspect-[2/3] overflow-hidden rounded-[2px] bg-[var(--bg-tertiary)]">
        {movie.poster_url ? (
          <img
            src={resolveMediaUrl(movie.poster_url)}
            alt={movie.title_ru}
            loading="lazy"
            className="w-full h-full object-cover transition-transform duration-[1400ms] ease-[cubic-bezier(0.76,0,0.24,1)] group-hover:scale-[1.08]"
          />
        ) : (
          <div className="w-full h-full grid place-items-center text-[var(--text-muted)]">
            <FilmIcon className="w-10 h-10 opacity-30" />
          </div>
        )}

        {/* Градиент на hover */}
        <span className="pointer-events-none absolute inset-0 bg-gradient-to-t from-black/85 via-black/0 to-black/0 opacity-0 group-hover:opacity-100 transition-opacity duration-700" />

        {/* Тонкая золотая рамка */}
        <span className="pointer-events-none absolute inset-2 border border-transparent group-hover:border-[var(--accent-yellow)]/70 transition-colors duration-700" />

        {/* Персонаж на hover */}
        {movie.pivot.character && (
          <span className="absolute bottom-3 left-3 right-3 font-serif italic text-xs text-white opacity-0 translate-y-2 group-hover:opacity-100 group-hover:translate-y-0 transition-all duration-500 leading-snug line-clamp-2">
            {movie.pivot.character}
          </span>
        )}

        {/* Стрелка */}
        <span className="absolute top-3 right-3 w-8 h-8 grid place-items-center bg-black/60 backdrop-blur-sm text-white opacity-0 translate-y-[-4px] group-hover:opacity-100 group-hover:translate-y-0 transition-all duration-500">
          <ArrowUpRightIcon className="w-3.5 h-3.5" />
        </span>
      </div>

      <div className="mt-4">
        <h3 className="font-serif text-base leading-snug line-clamp-2 group-hover:italic transition-[font-style] duration-300">
          {movie.title_ru}
        </h3>
        {movie.year && (
          <p className="mt-1.5 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] tabular-nums">
            {movie.year}
          </p>
        )}
      </div>
    </Link>
  );
}

/* ---------- Skeleton ---------- */

function PersonSkeleton() {
  return (
    <div className="min-h-screen bg-[var(--bg-primary)]">
      <section className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center gap-3 pb-5 border-b border-[var(--line)] animate-pulse">
            <div className="h-2.5 w-20 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-2.5 w-32 bg-[var(--bg-tertiary)] rounded" />
          </div>
        </div>
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-14 lg:pb-20 animate-pulse">
          <div className="grid lg:grid-cols-12 gap-10 items-end">
            <div className="lg:col-span-9 space-y-4">
              <div className="h-3 w-32 bg-[var(--bg-tertiary)] rounded" />
              <div className="h-24 w-3/4 bg-[var(--bg-tertiary)] rounded" />
            </div>
            <div className="lg:col-span-3 space-y-2">
              <div className="h-2.5 w-24 bg-[var(--bg-tertiary)] rounded ml-auto" />
              <div className="h-14 w-20 bg-[var(--bg-tertiary)] rounded ml-auto" />
              <div className="h-2.5 w-24 bg-[var(--bg-tertiary)] rounded ml-auto" />
            </div>
          </div>
        </div>
      </section>
      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 lg:gap-x-5 lg:gap-y-0 items-start animate-pulse">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className={STAGGER[i % 4]}>
              <div className="aspect-[2/3] rounded-[2px] bg-[var(--bg-tertiary)]" />
              <div className="h-4 w-4/5 bg-[var(--bg-tertiary)] rounded mt-4" />
              <div className="h-2.5 w-1/4 bg-[var(--bg-tertiary)] rounded mt-2" />
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

/* ---------- Not found ---------- */

function NotFoundState() {
  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-24 lg:py-32 text-center">
        <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
          404
        </p>
        <h1 className="font-serif text-4xl sm:text-5xl tracking-[-0.02em] mb-4">
          Персона не найдена
        </h1>
        <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
          Возможно, страница была удалена.
        </p>
        <div className="mt-10 flex justify-center">
          <Link href="/catalog" className="group inline-flex items-center gap-3">
            <ChevronLeftIcon className="w-4 h-4 transition-transform group-hover:-translate-x-0.5" />
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-primary)] border-b border-[var(--text-primary)] pb-0.5 group-hover:border-[var(--accent-yellow)] transition-colors">
              В каталог
            </span>
          </Link>
        </div>
      </div>
    </div>
  );
}

/* ---------- Error ---------- */

function ErrorState({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-24 lg:py-32 text-center">
        <div className="inline-flex items-center gap-3 mb-6">
          <ExclamationTriangleIcon className="w-4 h-4 text-[var(--accent-red)]" />
          <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--accent-red)]">
            Ошибка загрузки
          </p>
        </div>
        <h1 className="font-serif text-4xl sm:text-5xl tracking-[-0.02em] mb-4">
          Что-то пошло не так
        </h1>
        <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
          Попробуйте обновить страницу.
        </p>
        <div className="mt-10 flex flex-wrap items-center justify-center gap-6">
          <button onClick={onRetry} className="group inline-flex items-center gap-3">
            <span className="w-11 h-11 rounded-full bg-[var(--text-primary)] text-[var(--bg-primary)] grid place-items-center transition-transform duration-500 group-hover:rotate-[-8deg] group-hover:scale-105">
              <ArrowPathIcon className="w-5 h-5" />
            </span>
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-primary)] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
              Повторить
            </span>
          </button>
          <Link href="/catalog" className="group inline-flex items-center gap-3">
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
              В каталог
            </span>
            <span className="w-10 h-10 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
              <ArrowRightIcon className="w-4 h-4 transition-transform duration-500 group-hover:translate-x-0.5" />
            </span>
          </Link>
        </div>
      </div>
    </div>
  );
}