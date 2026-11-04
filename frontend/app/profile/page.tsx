'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { motion, useReducedMotion } from 'framer-motion';
import { profileApi, ProfileData } from '@/lib/api/profile';
import { STATUS_MAP, Entry } from '@/lib/api/entries';
import {
  StarIcon,
  FilmIcon,
  CalendarDaysIcon,
  ChevronLeftIcon,
  PencilSquareIcon,
  ArrowRightIcon,
  ArrowUpRightIcon,
  ExclamationTriangleIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline';
import { StarIcon as StarSolid } from '@heroicons/react/24/solid';
import toast from 'react-hot-toast';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const ACTIVITY_LIMIT = 5;

function plural(n: number, one: string, few: string, many: string): string {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return one;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return few;
  return many;
}

function formatMemberSince(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return 'недавно';
  const now = new Date();
  let months =
    (now.getFullYear() - d.getFullYear()) * 12 + (now.getMonth() - d.getMonth());
  if (now.getDate() < d.getDate()) months -= 1;
  if (months < 1) return 'меньше месяца';
  if (months < 12) {
    return `${months} ${plural(months, 'месяц', 'месяца', 'месяцев')}`;
  }
  const years = Math.floor(months / 12);
  const rest = months % 12;
  const yearsStr = `${years} ${plural(years, 'год', 'года', 'лет')}`;
  if (rest === 0) return yearsStr;
  return `${yearsStr} ${rest} мес.`;
}

function formatJoinDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('ru-RU', { month: 'long', year: 'numeric' });
}

type LoadState = 'loading' | 'ready' | 'error';

export default function ProfilePage() {
  const prefersReduced = useReducedMotion();
  const [data, setData] = useState<ProfileData | null>(null);
  const [state, setState] = useState<LoadState>('loading');

  const fetchProfile = async () => {
    setState('loading');
    try {
      const profileData = await profileApi.getProfile();
      setData(profileData);
      setState('ready');
    } catch {
      setState('error');
      toast.error('Не удалось загрузить профиль');
    }
  };

  useEffect(() => {
    fetchProfile();
  }, []);

  if (state === 'loading') return <ProfileSkeleton />;
  if (state === 'error' || !data) return <ErrorState onRetry={fetchProfile} />;

  const initials = data.user.name?.trim()?.[0]?.toUpperCase() || '?';
  const memberSince = formatMemberSince(data.user.created_at);
  const joinDate = formatJoinDate(data.user.created_at);
  const hasRating = data.stats.avg_rating != null && data.stats.avg_rating > 0;

  const activities = (data.recent_activity ?? []).slice(0, ACTIVITY_LIMIT) as Array<
    Pick<Entry, 'id' | 'media_id' | 'rating'> & {
      media?: { title_ru?: string; poster_url?: string };
      status_id?: number;
      status?: { name_ru: string; color: any };
      created_at?: string;
    }
  >;
  const hasMoreActivity = (data.recent_activity?.length ?? 0) > ACTIVITY_LIMIT;
  const genreCount = data.top_genres.length;
  const topGenre = data.top_genres[0];

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
              <ChevronLeftIcon className="w-3.5 h-3.5 transition-transform group-hover:-translate-x-0.5" />
              <span>На главную</span>
            </Link>
            <span className="hidden sm:inline">Профиль · @{data.user.login}</span>
          </div>
        </div>

        {/* Hero — editorial identity */}
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-14 lg:pb-20">
          <div className="grid lg:grid-cols-12 gap-10 items-end">
            <motion.div
              className="lg:col-span-8 min-w-0"
              initial={prefersReduced ? false : { opacity: 0, y: 24 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 1, ease: EASE_OUT }}
            >
              <div className="flex items-center gap-4 mb-8">
                <div
                  aria-hidden="true"
                  className="w-14 h-14 sm:w-16 sm:h-16 shrink-0 grid place-items-center bg-[var(--accent-yellow)] font-serif text-3xl text-black select-none"
                >
                  {initials}
                </div>
                <div className="min-w-0">
                  <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-secondary)] truncate">
                    @{data.user.login}
                  </p>
                  <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                    В клубе {memberSince} · {joinDate}
                  </p>
                </div>
              </div>

              <h1 className="font-serif text-[clamp(3rem,11vw,9rem)] leading-[0.82] tracking-[-0.045em] break-words">
                {data.user.name || 'Пользователь'}
                <span className="text-[var(--accent-yellow)]">.</span>
              </h1>
            </motion.div>

            <motion.div
              className="lg:col-span-4 lg:text-right"
              initial={prefersReduced ? false : { opacity: 0, y: 24 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 1, delay: 0.1, ease: EASE_OUT }}
            >
              <Link
                href="/profile/edit"
                className="group inline-flex items-center gap-3"
              >
                <span className="w-11 h-11 rounded-full border border-[var(--line)] grid place-items-center transition-colors duration-300 group-hover:border-[var(--text-primary)] group-hover:bg-[var(--text-primary)] group-hover:text-[var(--bg-primary)]">
                  <PencilSquareIcon className="w-5 h-5" />
                </span>
                <span className="font-mono text-[11px] uppercase tracking-[0.2em] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
                  Редактировать
                </span>
              </Link>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ============ STATS AS NARRATIVE ============ */}
      <section className="border-t border-[var(--line)] bg-[var(--bg-secondary)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
          <div className="grid lg:grid-cols-12 gap-10 lg:gap-14">
            <div className="lg:col-span-3">
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] lg:sticky lg:top-24">
                Статистика
              </p>
            </div>
            <div className="lg:col-span-9">
              <motion.p
                initial={prefersReduced ? false : { opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: '-80px' }}
                transition={{ duration: 0.8, ease: EASE_OUT }}
                className="font-serif text-2xl sm:text-3xl lg:text-4xl leading-[1.3] tracking-[-0.01em] max-w-4xl text-[var(--text-primary)]"
              >
                В вашем дневнике{' '}
                <span className="font-sans font-semibold text-[var(--accent-yellow)] tabular-nums">
                  {data.stats.total}
                </span>{' '}
                {plural(data.stats.total, 'отметка', 'отметки', 'отметок')}. Из них{' '}
                <span className="font-sans font-semibold text-[var(--accent-yellow)] tabular-nums">
                  {data.stats.watched}
                </span>{' '}
                — просмотрено.{' '}
                {hasRating ? (
                  <>
                    Средняя оценка —{' '}
                    <span className="font-sans font-semibold text-[var(--accent-yellow)] tabular-nums">
                      {data.stats.avg_rating}
                    </span>{' '}
                    <span className="text-[var(--text-muted)]">/ 10</span>.
                  </>
                ) : (
                  <span className="text-[var(--text-muted)]">Оценок пока нет.</span>
                )}
              </motion.p>

              {/* Быстрые ссылки — как строчная навигация */}
              <motion.div
                initial={prefersReduced ? false : { opacity: 0, y: 12 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: '-80px' }}
                transition={{ duration: 0.7, delay: 0.1, ease: EASE_OUT }}
                className="mt-10 flex flex-wrap items-center gap-x-10 gap-y-3"
              >
                <Link
                  href="/entries"
                  className="group inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] hover:text-[var(--text-primary)] border-b border-transparent hover:border-[var(--text-primary)] pb-0.5 transition-colors"
                >
                  Мои отметки
                  <ArrowRightIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:translate-x-0.5" />
                </Link>
                <Link
                  href="/lists"
                  className="group inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] hover:text-[var(--text-primary)] border-b border-transparent hover:border-[var(--text-primary)] pb-0.5 transition-colors"
                >
                  Мои списки
                  <ArrowRightIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:translate-x-0.5" />
                </Link>
              </motion.div>
            </div>
          </div>
        </div>
      </section>

      {/* ============ GENRES + ACTIVITY ============ */}
      <section className="border-t border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
          <div className="grid lg:grid-cols-12 gap-12 lg:gap-16">
            {/* Левый — жанры */}
            <motion.div
              className="lg:col-span-5"
              initial={prefersReduced ? false : { opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-80px' }}
              transition={{ duration: 0.8, ease: EASE_OUT }}
            >
              <div className="flex items-baseline justify-between pb-3 border-b border-[var(--line)] mb-8">
                <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                  Любимые жанры
                </p>
                <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                  {genreCount > 0 ? String(genreCount).padStart(2, '0') : '—'}
                </p>
              </div>

              <h2 className="font-serif text-3xl sm:text-4xl leading-[0.95] tracking-[-0.02em] mb-8">
                Что вы
                <br />
                <span className="italic">смотрите чаще</span>
              </h2>

              {data.top_genres.length === 0 ? (
                <div className="py-8 border-y border-[var(--line)]">
                  <p className="text-sm text-[var(--text-muted)] mb-4">
                    Пока недостаточно данных для статистики
                  </p>
                  <Link
                    href="/entries"
                    className="group inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border-b border-transparent hover:border-[var(--text-primary)] pb-0.5 transition-colors"
                  >
                    Добавить первую отметку
                    <ArrowRightIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:translate-x-0.5" />
                  </Link>
                </div>
              ) : (
                <GenreChart genres={data.top_genres} reducedMotion={!!prefersReduced} />
              )}
            </motion.div>

            {/* Правый — активность */}
            <motion.div
              className="lg:col-span-7"
              initial={prefersReduced ? false : { opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-80px' }}
              transition={{ duration: 0.8, delay: 0.1, ease: EASE_OUT }}
            >
              <div className="flex items-baseline justify-between pb-3 border-b border-[var(--line)] mb-8">
                <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                  Недавняя активность
                </p>
                <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                  {String(activities.length).padStart(2, '0')}
                </p>
              </div>

              <h2 className="font-serif text-3xl sm:text-4xl leading-[0.95] tracking-[-0.02em] mb-8">
                Последние
                <br />
                <span className="italic">отметки</span>
              </h2>

              {activities.length === 0 ? (
                <div className="py-8 border-y border-[var(--line)]">
                  <p className="text-sm text-[var(--text-muted)] mb-4">
                    Вы ещё ничего не отмечали
                  </p>
                  <Link
                    href="/catalog"
                    className="group inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border-b border-transparent hover:border-[var(--text-primary)] pb-0.5 transition-colors"
                  >
                    Открыть каталог
                    <ArrowRightIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:translate-x-0.5" />
                  </Link>
                </div>
              ) : (
                <>
                  <ul>
                    {activities.map((entry, i) => (
                      <motion.li
                        key={entry.id}
                        initial={prefersReduced ? false : { opacity: 0, y: 10 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        viewport={{ once: true, margin: '-40px' }}
                        transition={{
                          duration: 0.5,
                          delay: Math.min(i * 0.05, 0.3),
                          ease: EASE_OUT,
                        }}
                        className="border-b border-[var(--line)]"
                      >
                        <ActivityItem entry={entry} index={i} />
                      </motion.li>
                    ))}
                  </ul>
                  {hasMoreActivity && (
                    <div className="mt-8">
                      <Link
                        href="/entries"
                        className="group inline-flex items-center gap-3"
                      >
                        <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
                          Все отметки
                        </span>
                        <span className="w-9 h-9 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
                          <ArrowRightIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:translate-x-0.5" />
                        </span>
                      </Link>
                    </div>
                  )}
                </>
              )}
            </motion.div>
          </div>
        </div>
      </section>
    </div>
  );
}

/* ---------- График жанров ---------- */

function GenreChart({
  genres,
  reducedMotion,
}: {
  genres: { name_ru: string; count: number }[];
  reducedMotion: boolean;
}) {
  const maxCount = Math.max(...genres.map((g) => g.count), 1);

  return (
    <ul className="space-y-5">
      {genres.map((genre, i) => {
        const pct = Math.round((genre.count / maxCount) * 100);
        return (
          <li key={`${genre.name_ru}-${i}`}>
            <div className="flex items-baseline justify-between gap-3 mb-2">
              <span className="font-serif text-lg sm:text-xl tracking-[-0.005em] truncate">
                {genre.name_ru}
              </span>
              <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)] tabular-nums shrink-0">
                {genre.count} {plural(genre.count, 'фильм', 'фильма', 'фильмов')}
              </span>
            </div>
            <div
              className="h-[3px] bg-[var(--line)] relative overflow-hidden"
              role="progressbar"
              aria-valuenow={pct}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label={`${genre.name_ru}: ${genre.count}`}
            >
              <motion.div
                initial={reducedMotion ? { width: `${pct}%` } : { width: 0 }}
                whileInView={{ width: `${pct}%` }}
                viewport={{ once: true, margin: '-40px' }}
                transition={{
                  duration: 1.1,
                  delay: reducedMotion ? 0 : 0.1 + i * 0.08,
                  ease: EASE_OUT,
                }}
                className="absolute inset-y-0 left-0 bg-[var(--accent-yellow)]"
              />
            </div>
          </li>
        );
      })}
    </ul>
  );
}

/* ---------- Один элемент активности ---------- */

function ActivityItem({
  entry,
  index,
}: {
  entry: {
    id: number;
    media_id: number;
    rating?: number | null;
    media?: { title_ru?: string; poster_url?: string };
    status_id?: number;
    status?: { name_ru: string; color: any };
    created_at?: string;
  };
  index: number;
}) {
  const status =
    entry.status ?? (entry.status_id != null ? STATUS_MAP[entry.status_id] : undefined);
  const hasRating = entry.rating != null && entry.rating > 0;

  return (
    <Link
      href={`/media/${entry.media_id}`}
      className="group grid grid-cols-[auto_1fr_auto] items-center gap-4 sm:gap-5 py-5"
    >
      <span className="hidden sm:block font-mono text-[10px] tracking-[0.2em] text-[var(--text-muted)] min-w-[22px]">
        {String(index + 1).padStart(2, '0')}
      </span>

      <div className="shrink-0 w-12 sm:w-14 aspect-[2/3] overflow-hidden bg-[var(--bg-tertiary)] relative">
        {entry.media?.poster_url ? (
          <img
            src={entry.media.poster_url}
            alt=""
            loading="lazy"
            className="w-full h-full object-cover transition-transform duration-[1200ms] ease-[cubic-bezier(0.76,0,0.24,1)] group-hover:scale-[1.06]"
          />
        ) : (
          <div className="w-full h-full grid place-items-center">
            <FilmIcon className="w-4 h-4 text-[var(--text-muted)] opacity-40" />
          </div>
        )}
        <span className="pointer-events-none absolute inset-1 border border-transparent group-hover:border-[var(--accent-yellow)]/60 transition-colors duration-500" />
      </div>

      <div className="min-w-0">
        <h3 className="font-serif text-lg sm:text-xl leading-snug tracking-[-0.005em] truncate group-hover:italic transition-[font-style] duration-300">
          {entry.media?.title_ru || 'Без названия'}
        </h3>
        <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)]">
          {status && (
            <span className="inline-flex items-center gap-1.5">
              <span
                className="w-1 h-1 rounded-full"
                style={{ background: `var(--accent-${status.color})` }}
              />
              {status.name_ru}
            </span>
          )}
          {hasRating && (
            <span className="inline-flex items-center gap-1">
              <StarSolid className="w-3 h-3 text-[var(--accent-yellow)]" />
              <span className="text-[var(--text-secondary)] tabular-nums">
                {entry.rating}
              </span>
              <span>/10</span>
            </span>
          )}
        </div>
      </div>

      <span className="w-8 h-8 grid place-items-center text-[var(--text-muted)] opacity-0 group-hover:opacity-100 transition-opacity duration-500">
        <ArrowUpRightIcon className="w-4 h-4" />
      </span>
    </Link>
  );
}

/* ---------- Skeleton ---------- */

function ProfileSkeleton() {
  return (
    <div className="min-h-screen bg-[var(--bg-primary)]">
      <section className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] animate-pulse">
            <div className="h-2.5 w-24 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-2.5 w-32 bg-[var(--bg-tertiary)] rounded" />
          </div>
        </div>
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-14 lg:pb-20 animate-pulse">
          <div className="grid lg:grid-cols-12 gap-10 items-end">
            <div className="lg:col-span-8 space-y-4">
              <div className="h-14 w-14 bg-[var(--bg-tertiary)] rounded" />
              <div className="h-20 w-3/4 bg-[var(--bg-tertiary)] rounded" />
            </div>
            <div className="lg:col-span-4 flex lg:justify-end">
              <div className="h-11 w-40 bg-[var(--bg-tertiary)] rounded-full" />
            </div>
          </div>
        </div>
      </section>
      <section className="border-t border-[var(--line)] bg-[var(--bg-secondary)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24 animate-pulse">
          <div className="grid lg:grid-cols-12 gap-10">
            <div className="lg:col-span-3">
              <div className="h-2.5 w-24 bg-[var(--bg-tertiary)] rounded" />
            </div>
            <div className="lg:col-span-9 space-y-4">
              <div className="h-4 w-full bg-[var(--bg-tertiary)] rounded" />
              <div className="h-4 w-2/3 bg-[var(--bg-tertiary)] rounded" />
              <div className="h-4 w-5/6 bg-[var(--bg-tertiary)] rounded" />
            </div>
          </div>
        </div>
      </section>
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
          Не удалось загрузить профиль
        </h1>
        <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
          Проверьте соединение и попробуйте ещё раз.
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
          <Link href="/" className="group inline-flex items-center gap-3">
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
              На главную
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