// frontend/components/ui/DirectorMovies.tsx
'use client';

import Link from 'next/link';
import Image from 'next/image';
import { useEffect, useRef, useState } from 'react';
import {
  FilmIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ArrowUpRightIcon,
} from '@heroicons/react/24/outline';
import { SimilarMoviesResponse } from '@/lib/api/media';
import { resolveMediaUrl } from '@/lib/utils/media-url';

interface DirectorMoviesProps {
  data: SimilarMoviesResponse;
}

type SimilarMovie = {
  id: number;
  title_ru: string;
  poster_url?: string | null;
  year?: number;
  release_date?: string;
};

function getMovieYear(movie: SimilarMovie): number | null {
  if (movie.year != null && !Number.isNaN(movie.year)) return movie.year;
  if (movie.release_date) {
    const d = new Date(movie.release_date);
    if (!Number.isNaN(d.getTime())) return d.getFullYear();
  }
  return null;
}

export default function DirectorMovies({ data }: DirectorMoviesProps) {
  const scrollRef = useRef<HTMLUListElement>(null);
  const [canLeft, setCanLeft] = useState(false);
  const [canRight, setCanRight] = useState(false);

  const movies = (data?.movies ?? []) as SimilarMovie[];
  const director = data?.director;

  useEffect(() => {
    if (movies.length === 0) return;
    const el = scrollRef.current;
    if (!el) return;

    const update = () => {
      setCanLeft(el.scrollLeft > 4);
      setCanRight(el.scrollLeft + el.clientWidth < el.scrollWidth - 4);
    };

    update();
    el.addEventListener('scroll', update, { passive: true });
    const ro = new ResizeObserver(update);
    ro.observe(el);

    return () => {
      el.removeEventListener('scroll', update);
      ro.disconnect();
    };
  }, [movies.length]);

  if (!director || movies.length === 0) return null;

  const directorHref =
    director.id != null ? `/persons/${director.id}` : undefined;

  const scrollBy = (dir: 'left' | 'right') => {
    const el = scrollRef.current;
    if (!el) return;
    const amount = Math.max(el.clientWidth * 0.8, 240);
    el.scrollBy({
      left: dir === 'left' ? -amount : amount,
      behavior: 'smooth',
    });
  };

  return (
    <section aria-labelledby="director-movies-heading">
      {/* Заголовок — редакционная полоса */}
      <div className="grid lg:grid-cols-12 gap-6 items-end pb-6 mb-10 border-b border-[var(--line)]">
        <div className="lg:col-span-8">
          <div className="flex items-center gap-3 mb-4">
            <FilmIcon
              className="w-3 h-3 text-[var(--accent-yellow)]"
              aria-hidden="true"
            />
            <span
              id="director-movies-heading"
              className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]"
            >
              Другие фильмы режиссёра
            </span>
          </div>

          {directorHref ? (
            <Link href={directorHref} className="group inline-flex items-baseline gap-3">
              <span className="font-serif text-3xl sm:text-4xl lg:text-5xl leading-[0.92] tracking-[-0.025em] text-[var(--text-primary)] group-hover:italic transition-[font-style] duration-300">
                {director.name}
              </span>
              <ArrowUpRightIcon
                className="w-4 h-4 shrink-0 text-[var(--text-muted)] transition-transform duration-500 group-hover:rotate-45 group-hover:text-[var(--text-primary)]"
                aria-hidden="true"
              />
            </Link>
          ) : (
            <span className="font-serif text-3xl sm:text-4xl lg:text-5xl leading-[0.92] tracking-[-0.025em] text-[var(--text-primary)]">
              {director.name}
            </span>
          )}
        </div>

        <div className="lg:col-span-4 lg:text-right">
          <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] tabular-nums">
            {String(movies.length).padStart(2, '0')}{' '}
            {movies.length === 1
              ? 'работа'
              : movies.length < 5
                ? 'работы'
                : 'работ'}
          </p>
        </div>
      </div>

      {/* Карусель */}
      <div className="relative">
        <ul
          ref={scrollRef}
          role="list"
          className="flex gap-4 lg:gap-5 overflow-x-auto overscroll-x-contain pb-4 snap-x snap-mandatory scrollbar-none -mx-6 px-6 lg:mx-0 lg:px-0"
          style={{ scrollbarWidth: 'none' }}
        >
          {movies.map((movie, i) => {
            const year = getMovieYear(movie);
            return (
              <li
                key={movie.id}
                className="flex-shrink-0 w-[140px] sm:w-[160px] lg:w-[180px] snap-start"
              >
                <MovieCard movie={movie} year={year} index={i} eager={i === 0} />
              </li>
            );
          })}
        </ul>

        {/* Стрелки — минималистичные круги, только на десктопе */}
        {canLeft && (
          <button
            type="button"
            onClick={() => scrollBy('left')}
            aria-label="Прокрутить влево"
            className="hidden md:grid absolute left-0 top-1/2 -translate-y-1/2 z-10 w-10 h-10 place-items-center rounded-full border border-[var(--line)] bg-[var(--bg-primary)]/95 backdrop-blur text-[var(--text-primary)] hover:border-[var(--text-primary)] transition-colors"
          >
            <ChevronLeftIcon className="w-4 h-4" aria-hidden="true" />
          </button>
        )}
        {canRight && (
          <button
            type="button"
            onClick={() => scrollBy('right')}
            aria-label="Прокрутить вправо"
            className="hidden md:grid absolute right-0 top-1/2 -translate-y-1/2 z-10 w-10 h-10 place-items-center rounded-full border border-[var(--line)] bg-[var(--bg-primary)]/95 backdrop-blur text-[var(--text-primary)] hover:border-[var(--text-primary)] transition-colors"
          >
            <ChevronRightIcon className="w-4 h-4" aria-hidden="true" />
          </button>
        )}
      </div>
    </section>
  );
}


function MovieCard({
  movie,
  year,
  index,
  eager,
}: {
  movie: SimilarMovie;
  year: number | null;
  index: number;
  eager: boolean;
}) {
  const [imageFailed, setImageFailed] = useState(false);
  const posterUrl = resolveMediaUrl(movie.poster_url);
  const showImage = posterUrl && !imageFailed;

  return (
    <Link
      href={`/media/${movie.id}`}
      className="group block focus-visible:outline-none"
      aria-label={`Открыть «${movie.title_ru}»${year ? `, ${year}` : ''}`}
    >
      <div className="relative aspect-[2/3] overflow-hidden rounded-[2px] bg-[var(--bg-tertiary)]">
        {showImage ? (
          <Image
            src={resolveMediaUrl(movie.poster_url)!}
            alt={movie.title_ru}
            fill
            sizes="(max-width: 640px) 128px, 160px"
            className="object-cover"
          />
        ) : (
          <div className="w-full h-full grid place-items-center text-[var(--text-muted)]">
            <FilmIcon className="w-8 h-8 opacity-30" aria-hidden="true" />
          </div>
        )}

        {/* Градиент на hover */}
        <span className="pointer-events-none absolute inset-0 bg-gradient-to-t from-black/85 via-black/0 to-black/0 opacity-0 group-hover:opacity-100 transition-opacity duration-700" />

        {/* Тонкая золотая рамка */}
        <span className="pointer-events-none absolute inset-2 border border-transparent group-hover:border-[var(--accent-yellow)]/70 transition-colors duration-700" />

        {/* Порядковый номер */}
        <span className="absolute top-3 left-3 font-mono text-[10px] tracking-[0.15em] text-white/60 mix-blend-difference opacity-0 group-hover:opacity-100 transition-opacity duration-500">
          {String(index + 1).padStart(2, '0')}
        </span>

        {/* Стрелка снизу */}
        <span className="absolute bottom-3 right-3 w-8 h-8 grid place-items-center bg-black/60 backdrop-blur-sm text-white opacity-0 translate-y-2 group-hover:opacity-100 group-hover:translate-y-0 transition-all duration-500">
          <ArrowUpRightIcon className="w-3.5 h-3.5" />
        </span>
      </div>

      <div className="mt-4">
        <p className="font-serif text-base leading-snug line-clamp-2 text-[var(--text-primary)] group-hover:italic transition-[font-style] duration-300">
          {movie.title_ru}
        </p>
        {year != null && (
          <p className="mt-1.5 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] tabular-nums">
            {year}
          </p>
        )}
      </div>
    </Link>
  );
}