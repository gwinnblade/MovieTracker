'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { motion, useReducedMotion } from 'framer-motion';
import { publicListsApi, UserList } from '@/lib/api/lists';
import { Media } from '@/lib/api/media';
import { resolveMediaUrl } from '@/lib/utils/media-url';
import toast from 'react-hot-toast';
import {
  FilmIcon,
  ShareIcon,
  CheckIcon,
  ArrowRightIcon,
  ArrowUpRightIcon,
  CalendarDaysIcon,
  ChevronLeftIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

const STAGGER = ['', 'lg:mt-16', 'lg:mt-4', 'lg:mt-24'];

function plural(n: number, one: string, few: string, many: string): string {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return one;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return few;
  return many;
}

type LoadState = 'loading' | 'ready' | 'notfound' | 'private' | 'error';

export default function PublicListClient({ token }: { token: string }) {
  const prefersReduced = useReducedMotion();
  const [list, setList] = useState<UserList | null>(null);
  const [state, setState] = useState<LoadState>('loading');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!token) {
      setState('notfound');
      return;
    }
    let cancelled = false;

    (async () => {
      setState('loading');
      try {
        const data = await publicListsApi.getByToken(token);
        if (cancelled) return;
        setList(data);
        setState('ready');
      } catch (err: any) {
        if (cancelled) return;
        const status = err?.response?.status;
        if (status === 404) setState('notfound');
        else if (status === 403) setState('private');
        else setState('error');
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [token]);

  const handleShare = async () => {
    const url = window.location.href;
    try {
      if (typeof navigator.share === 'function') {
        await navigator.share({ title: list?.name ?? 'MovieTracker', url });
        return;
      }
      await navigator.clipboard.writeText(url);
      setCopied(true);
      toast.success('Ссылка скопирована');
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* user cancelled */
    }
  };

  if (state === 'loading') return <PublicListSkeleton />;
  if (state === 'notfound') return <NotFoundState />;
  if (state === 'private') return <PrivateState />;
  if (state === 'error' || !list) return <ErrorState />;

  const mediaList: Media[] = list.media ?? [];
  const count = mediaList.length;
  const countLabel = `${count} ${plural(count, 'фильм', 'фильма', 'фильмов')}`;
  const author = list.user?.name?.trim();
  const authorLogin = list.user?.login;

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
              <FilmIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:rotate-[-8deg]" />
              <span>MovieTracker</span>
            </Link>

            <button
              onClick={handleShare}
              aria-label="Поделиться списком"
              className="group inline-flex items-center gap-2 hover:text-[var(--text-primary)] transition-colors"
            >
              {copied ? (
                <>
                  <CheckIcon className="w-3.5 h-3.5 text-[var(--accent-green)]" />
                  <span>Скопировано</span>
                </>
              ) : (
                <>
                  <ShareIcon className="w-3.5 h-3.5" />
                  <span>Поделиться</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Hero */}
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
                  Публичный список
                </span>
                <span className="text-[var(--text-muted)]">·</span>
                <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                  {countLabel}
                </span>
              </div>

              <h1 className="font-serif text-[clamp(2.75rem,11vw,9rem)] leading-[0.83] tracking-[-0.045em] break-words">
                {list.name}
                <span className="text-[var(--accent-yellow)]">.</span>
              </h1>

              {list.description && (
                <p className="mt-8 max-w-2xl text-base sm:text-lg text-[var(--text-secondary)] leading-relaxed">
                  {list.description}
                </p>
              )}

              {author && (
                <div className="mt-8 flex flex-wrap items-center gap-x-4 gap-y-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                  <span className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--text-primary)]/60" />
                    <span>Составил</span>
                  </span>
                  <span className="text-[var(--text-primary)] normal-case tracking-normal font-serif text-base">
                    {author}
                  </span>
                  {authorLogin && (
                    <span className="font-mono text-[10px]">@{authorLogin}</span>
                  )}
                </div>
              )}
            </motion.div>

            {/* CTA */}
            <motion.div
              className="lg:col-span-3 lg:text-right"
              initial={prefersReduced ? false : { opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.9, delay: 0.1, ease: EASE_OUT }}
            >
              <Link href="/register" className="group inline-flex items-center gap-3">
                <span className="w-11 h-11 rounded-full bg-[var(--text-primary)] text-[var(--bg-primary)] grid place-items-center transition-transform duration-500 group-hover:rotate-[-8deg] group-hover:scale-105">
                  <ArrowRightIcon className="w-5 h-5" />
                </span>
                <span className="font-mono text-[11px] uppercase tracking-[0.2em] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
                  Создать свой
                </span>
              </Link>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ============ MOVIES ============ */}
      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
        {count === 0 ? (
          <EmptyList />
        ) : (
          <>
            <div className="flex items-center justify-between pb-3 border-b border-[var(--line)] mb-8 lg:mb-10">
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                Содержимое подборки
              </p>
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                {String(count).padStart(2, '0')}
              </p>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 lg:gap-x-5 lg:gap-y-0 items-start">
              {mediaList.map((media, i) => (
                <motion.div
                  key={media.id}
                  initial={prefersReduced ? false : { opacity: 0, y: 14 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{
                    duration: 0.6,
                    delay: Math.min(i * 0.05, 0.4),
                    ease: EASE_OUT,
                  }}
                  className={STAGGER[i % 4]}
                >
                  <MediaCard media={media} index={i} />
                </motion.div>
              ))}
            </div>

            {/* CTA under list */}
            <motion.div
              initial={prefersReduced ? false : { opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-80px' }}
              transition={{ duration: 0.8, ease: EASE_OUT }}
              className="mt-24 lg:mt-32 pt-10 border-t border-[var(--line)]"
            >
              <div className="grid lg:grid-cols-12 gap-8 items-end">
                <div className="lg:col-span-8">
                  <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-5">
                    Своя коллекция
                  </p>
                  <h2 className="font-serif text-4xl sm:text-5xl lg:text-6xl leading-[0.9] tracking-[-0.03em]">
                    Соберите свой список
                    <br />
                    <span className="italic">— и поделитесь с друзьями</span>
                  </h2>
                </div>
                <div className="lg:col-span-4 lg:text-right">
                  <div className="flex flex-wrap items-center lg:justify-end gap-x-8 gap-y-3">
                    <Link href="/register" className="group inline-flex items-center gap-3">
                      <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-primary)] border-b border-[var(--text-primary)] pb-0.5 group-hover:border-[var(--accent-yellow)] transition-colors">
                        Создать аккаунт
                      </span>
                      <ArrowRightIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:translate-x-0.5" />
                    </Link>
                    <Link href="/catalog" className="group inline-flex items-center gap-3">
                      <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
                        Открыть каталог
                      </span>
                      <span className="w-9 h-9 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
                        <ArrowUpRightIcon className="w-3.5 h-3.5" />
                      </span>
                    </Link>
                  </div>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </section>
    </div>
  );
}

/* ---------- Карточка фильма ---------- */

function MediaCard({ media, index }: { media: Media; index: number }) {
  const posterUrl = resolveMediaUrl(media.poster_url);
  const year = media.release_date ? new Date(media.release_date).getFullYear() : null;

  return (
    <Link href={`/media/${media.id}`} className="group block">
      <div className="relative aspect-[2/3] overflow-hidden rounded-[2px] bg-[var(--bg-tertiary)]">
        {posterUrl ? (
          <img
            src={posterUrl}
            alt=""
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

        {/* Порядковый номер */}
        <span className="absolute top-3 left-3 font-mono text-[10px] tracking-[0.15em] text-white/60 mix-blend-difference opacity-0 group-hover:opacity-100 transition-opacity duration-500">
          {String(index + 1).padStart(2, '0')}
        </span>

        {/* Тип */}
        {media.type && (
          <span className="absolute top-3 right-3 font-mono text-[9px] uppercase tracking-[0.15em] text-white/80 opacity-0 group-hover:opacity-100 transition-opacity duration-500">
            {media.type.name_ru}
          </span>
        )}

        {/* Стрелка снизу */}
        <span className="absolute bottom-3 right-3 w-8 h-8 grid place-items-center bg-black/60 backdrop-blur-sm text-white opacity-0 translate-y-2 group-hover:opacity-100 group-hover:translate-y-0 transition-all duration-500">
          <ArrowUpRightIcon className="w-3.5 h-3.5" />
        </span>
      </div>

      <div className="mt-4">
        <h3 className="font-serif text-base lg:text-lg leading-snug line-clamp-2 group-hover:italic transition-[font-style] duration-300">
          {media.title_ru}
        </h3>
        {year && (
          <p className="mt-1.5 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] tabular-nums">
            {year}
          </p>
        )}
      </div>
    </Link>
  );
}

/* ---------- Пустой стейт ---------- */

function EmptyList() {
  return (
    <div className="py-24 lg:py-32 text-center border-y border-[var(--line)]">
      <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
        Пусто
      </p>
      <h2 className="font-serif text-4xl sm:text-5xl tracking-[-0.02em] mb-4">
        В этом списке пока пусто
      </h2>
      <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
        Автор ещё не добавил сюда фильмы. Загляните позже — список может пополниться.
      </p>
      <div className="mt-10 flex justify-center">
        <Link href="/catalog" className="group inline-flex items-center gap-3">
          <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
            Открыть каталог
          </span>
          <span className="w-10 h-10 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
            <ArrowRightIcon className="w-4 h-4 transition-transform duration-500 group-hover:translate-x-0.5" />
          </span>
        </Link>
      </div>
    </div>
  );
}

/* ---------- Состояния ---------- */

function NotFoundState() {
  return (
    <StateShell
      tag="404"
      title="Список не найден"
      text="Возможно, ссылка повреждена или список был удалён. Проверьте адрес и попробуйте ещё раз."
    />
  );
}

function PrivateState() {
  return (
    <StateShell
      tag="Приватно"
      title="Список стал приватным"
      text="Автор закрыл доступ к этому списку. Свяжитесь с ним, если хотите получить доступ."
    />
  );
}

function ErrorState() {
  return (
    <StateShell
      tag="Ошибка"
      title="Не удалось загрузить список"
      text="Проверьте соединение с интернетом и попробуйте ещё раз."
      onRetry={() => window.location.reload()}
      error
    />
  );
}

function StateShell({
  tag,
  title,
  text,
  onRetry,
  error,
}: {
  tag: string;
  title: string;
  text: string;
  onRetry?: () => void;
  error?: boolean;
}) {
  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-24 lg:py-32 text-center">
        <div className="inline-flex items-center gap-3 mb-6">
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{
              background: error ? 'var(--accent-red)' : 'var(--accent-yellow)',
            }}
          />
          <p
            className="font-mono text-[10px] uppercase tracking-[0.25em]"
            style={{
              color: error ? 'var(--accent-red)' : 'var(--text-muted)',
            }}
          >
            {tag}
          </p>
        </div>
        <h1 className="font-serif text-4xl sm:text-5xl tracking-[-0.02em] mb-4">
          {title}
        </h1>
        <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
          {text}
        </p>
        <div className="mt-10 flex flex-wrap items-center justify-center gap-6">
          {onRetry && (
            <button onClick={onRetry} className="group inline-flex items-center gap-3">
              <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-primary)] border-b border-[var(--text-primary)] pb-0.5 group-hover:border-[var(--accent-yellow)] transition-colors">
                Повторить
              </span>
              <ExclamationTriangleIcon className="w-4 h-4 text-[var(--accent-red)]" />
            </button>
          )}
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

/* ---------- Skeleton ---------- */

function PublicListSkeleton() {
  return (
    <div className="min-h-screen bg-[var(--bg-primary)]">
      <section className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] animate-pulse">
            <div className="h-2.5 w-32 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-2.5 w-24 bg-[var(--bg-tertiary)] rounded" />
          </div>
        </div>
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-14 lg:pb-20 animate-pulse">
          <div className="grid lg:grid-cols-12 gap-10 items-end">
            <div className="lg:col-span-9 space-y-4">
              <div className="h-2.5 w-40 bg-[var(--bg-tertiary)] rounded" />
              <div className="h-24 w-3/4 bg-[var(--bg-tertiary)] rounded" />
              <div className="h-4 w-1/2 bg-[var(--bg-tertiary)] rounded" />
            </div>
            <div className="lg:col-span-3 flex lg:justify-end">
              <div className="h-11 w-40 bg-[var(--bg-tertiary)] rounded-full" />
            </div>
          </div>
        </div>
      </section>
      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24 animate-pulse">
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 lg:gap-x-5 lg:gap-y-0 items-start">
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