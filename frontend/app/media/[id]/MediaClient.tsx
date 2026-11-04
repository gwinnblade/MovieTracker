'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import { motion, useReducedMotion } from 'framer-motion';
import { mediaApi, Media, SimilarMoviesResponse } from '@/lib/api/media';
import { entriesApi, Entry, STATUS_MAP } from '@/lib/api/entries';
import EpisodeList from '@/components/ui/EpisodeList';
import CreditsList from '@/components/ui/CreditsList';
import EntryForm from '@/components/ui/EntryForm';
import AddToListModal from '@/components/ui/AddToListModal';
import DirectorMovies from '@/components/ui/DirectorMovies';
import { resolveMediaUrl } from '@/lib/utils/media-url';
import toast from 'react-hot-toast';
import {
  FilmIcon,
  ChevronLeftIcon,
  PlusCircleIcon,
  ListBulletIcon,
  ShareIcon,
  ArrowPathIcon,
  CheckIcon,
  PencilSquareIcon,
  ExclamationTriangleIcon,
  ArrowRightIcon,
} from '@heroicons/react/24/outline';
import { StarIcon as StarSolid } from '@heroicons/react/24/solid';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

const TYPE_COLOR: Record<string, 'yellow' | 'blue' | 'green' | 'purple'> = {
  movie: 'yellow',
  series: 'blue',
  anime: 'green',
  cartoon: 'purple',
};

type LoadState = 'loading' | 'ready' | 'notfound' | 'error';

export default function MediaClient({ id }: { id: number }) {
  const prefersReduced = useReducedMotion();

  const [media, setMedia] = useState<Media | null>(null);
  const [userEntry, setUserEntry] = useState<Entry | null>(null);
  const [state, setState] = useState<LoadState>('loading');

  const [isEntryModalOpen, setIsEntryModalOpen] = useState(false);
  const [showListModal, setShowListModal] = useState(false);
  const [copied, setCopied] = useState(false);
  const [similarData, setSimilarData] = useState<SimilarMoviesResponse | null>(null);
  const [similarState, setSimilarState] = useState<'loading' | 'ready' | 'empty'>('loading');

  const fetchEntryFor = useCallback(async (mediaId: number): Promise<Entry | null> => {
    try {
      const entries = await entriesApi.getList();
      return Array.isArray(entries)
        ? entries.find((e) => e.media_id === mediaId) ?? null
        : null;
    } catch {
      return null;
    }
  }, []);

  const loadData = useCallback(async () => {
    if (!id) {
      setState('notfound');
      return;
    }
    setState('loading');
    try {
      const mediaData = await mediaApi.getById(id);
      setMedia(mediaData);
      const entry = await fetchEntryFor(id);
      setUserEntry(entry);
      setState('ready');
    } catch (error: any) {
      setState(error?.response?.status === 404 ? 'notfound' : 'error');
    }
  }, [id, fetchEntryFor]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    setSimilarData(null);
    setSimilarState('loading');

    (async () => {
      try {
        const data = await mediaApi.getSimilar(id);
        if (cancelled) return;
        setSimilarData(data);
        setSimilarState(data ? 'ready' : 'empty');
      } catch {
        if (!cancelled) setSimilarState('empty');
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [id]);

  const handleShare = async () => {
    if (!media) return;
    const url = window.location.href;
    try {
      if (typeof navigator.share === 'function') {
        await navigator.share({ title: media.title_ru, url });
        return;
      }
      await navigator.clipboard.writeText(url);
      setCopied(true);
      toast.success('Ссылка скопирована');
      setTimeout(() => setCopied(false), 2000);
    } catch {}
  };

  const handleEntrySaved = async () => {
    if (!media) return;
    setIsEntryModalOpen(false);
    const entry = await fetchEntryFor(media.id);
    setUserEntry(entry);
  };

  if (state === 'loading') return <MediaSkeleton />;
  if (state === 'notfound') return <NotFoundState />;
  if (state === 'error') return <ErrorState onRetry={loadData} />;
  if (!media) return <NotFoundState />;

  const year = media.release_date ? new Date(media.release_date).getFullYear() : null;
  const status = userEntry ? STATUS_MAP[userEntry.status_id] : null;
  const hasRating = userEntry?.rating != null;
  const showSimilar = similarState === 'loading' || similarState === 'ready';

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
            {media.type && (
              <>
                <span className="text-[var(--text-muted)]/50 shrink-0">/</span>
                <Link
                  href={`/catalog?type=${media.type.code}`}
                  className="hover:text-[var(--text-primary)] transition-colors truncate"
                >
                  {media.type.name_ru}
                </Link>
              </>
            )}
            <span className="text-[var(--text-muted)]/50 shrink-0">/</span>
            <span className="text-[var(--text-secondary)] truncate min-w-0">
              {media.title_ru}
            </span>
          </nav>
        </div>
      </section>

      {/* ============ HERO ============ */}
      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-16 lg:pb-24">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-14">
          {/* Постер — sticky */}
          <motion.div
            className="lg:col-span-4 xl:col-span-3"
            initial={prefersReduced ? false : { opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, ease: EASE_OUT }}
          >
            <div className="lg:sticky lg:top-24 mx-auto lg:mx-0 w-full max-w-[280px] lg:max-w-none">
              <div className="relative aspect-[2/3] overflow-hidden rounded-[2px] bg-[var(--bg-tertiary)]">
                {media.poster_url ? (
                    <Image
                        src={resolveMediaUrl(media.poster_url)!}
                        alt={`Постер «${media.title_ru}»`}
                        fill
                        sizes="(max-width: 768px) 280px, 300px"
                        className="object-cover"
                        priority
                    />
                  ) : (
                  <div className="w-full h-full grid place-items-center text-[var(--text-muted)]">
                    <FilmIcon className="w-14 h-14 opacity-25" aria-hidden="true" />
                  </div>
                )}
                <span className="pointer-events-none absolute inset-3 border border-white/10" />
              </div>

              {/* Под постером — метаданные */}
              <div className="mt-6 space-y-3">
                {media.type && (
                  <div className="flex items-baseline justify-between gap-3 border-b border-[var(--line)] pb-2.5">
                    <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                      Формат
                    </span>
                    <span className="font-serif text-sm text-[var(--text-primary)]">
                      {media.type.name_ru}
                    </span>
                  </div>
                )}
                {year && (
                  <div className="flex items-baseline justify-between gap-3 border-b border-[var(--line)] pb-2.5">
                    <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                      Год
                    </span>
                    <span className="font-mono text-sm tabular-nums text-[var(--text-primary)]">
                      {year}
                    </span>
                  </div>
                )}
                {status && (
                  <div className="flex items-baseline justify-between gap-3 border-b border-[var(--line)] pb-2.5">
                    <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                      Статус
                    </span>
                    <span className="inline-flex items-center gap-2">
                      <span
                        className="w-1.5 h-1.5 rounded-full"
                        style={{ background: `var(--accent-${status.color})` }}
                      />
                      <span className="font-serif text-sm text-[var(--text-primary)]">
                        {status.name}
                      </span>
                    </span>
                  </div>
                )}
                {hasRating && (
                  <div className="flex items-baseline justify-between gap-3 border-b border-[var(--line)] pb-2.5">
                    <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                      Оценка
                    </span>
                    <span className="inline-flex items-baseline gap-1">
                      <StarSolid className="w-3 h-3 text-[var(--accent-yellow)] self-center" />
                      <span className="font-serif text-lg tabular-nums">
                        {userEntry!.rating}
                      </span>
                      <span className="font-mono text-[10px] text-[var(--text-muted)]">/10</span>
                    </span>
                  </div>
                )}
              </div>
            </div>
          </motion.div>

          {/* Контент */}
          <motion.div
            className="lg:col-span-8 xl:col-span-9 min-w-0"
            initial={prefersReduced ? false : { opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, delay: 0.1, ease: EASE_OUT }}
          >
            {media.type && (
              <div className="flex items-center gap-3 mb-6">
                <span
                  className="w-1.5 h-1.5 rounded-full"
                  style={{ background: `var(--accent-${TYPE_COLOR[media.type.code ?? ''] ?? 'yellow'})` }}
                />
                <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-secondary)]">
                  {media.type.name_ru}
                </span>
                {year && (
                  <>
                    <span className="text-[var(--text-muted)]">·</span>
                    <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                      {year}
                    </span>
                  </>
                )}
              </div>
            )}

            <h1 className="font-serif text-[clamp(2.75rem,7vw,6.5rem)] leading-[0.86] tracking-[-0.04em] break-words">
              {media.title_ru}
              <span className="text-[var(--accent-yellow)]">.</span>
            </h1>

            {media.title_en && (
              <p className="mt-6 font-serif italic text-xl sm:text-2xl text-[var(--text-secondary)] tracking-[-0.01em]">
                {media.title_en}
              </p>
            )}

            {(media.genres?.length ?? 0) > 0 && (
              <div className="mt-8 flex flex-wrap gap-x-4 gap-y-2">
                {media.genres!.map((g, i) => (
                  <span key={g.id} className="inline-flex items-center gap-4">
                    {i > 0 && <span className="text-[var(--text-muted)]/40">·</span>}
                    <Link
                      href={`/catalog?genre=${g.id}`}
                      className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border-b border-transparent hover:border-[var(--text-primary)] pb-0.5 transition-colors"
                    >
                      {g.name_ru}
                    </Link>
                  </span>
                ))}
              </div>
            )}

            {media.description_ru && (
              <div className="mt-12 max-w-3xl">
                <Description text={media.description_ru} />
              </div>
            )}

            {/* Действия */}
            <div className="mt-12 pt-8 border-t border-[var(--line)] flex flex-wrap items-center gap-x-8 gap-y-4">
              <button
                onClick={() => setIsEntryModalOpen(true)}
                className="group inline-flex items-center gap-3"
              >
                <span className="w-11 h-11 rounded-full bg-[var(--text-primary)] text-[var(--bg-primary)] grid place-items-center transition-transform duration-500 group-hover:rotate-[-8deg] group-hover:scale-105">
                  {userEntry ? (
                    <PencilSquareIcon className="w-5 h-5" />
                  ) : (
                    <PlusCircleIcon className="w-5 h-5" />
                  )}
                </span>
                <span className="font-mono text-[11px] uppercase tracking-[0.2em] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
                  {userEntry ? 'Изменить отметку' : 'Отметить'}
                </span>
              </button>

              <button
                onClick={() => setShowListModal(true)}
                className="group inline-flex items-center gap-3"
              >
                <span className="w-11 h-11 rounded-full border border-[var(--line)] grid place-items-center transition-colors duration-300 group-hover:border-[var(--text-primary)]">
                  <ListBulletIcon className="w-5 h-5" />
                </span>
                <span className="font-mono text-[11px] uppercase tracking-[0.2em] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
                  В список
                </span>
              </button>

              <button
                onClick={handleShare}
                aria-label="Поделиться ссылкой"
                className="group inline-flex items-center gap-3 ml-auto"
              >
                <span className="font-mono text-[11px] uppercase tracking-[0.2em] pb-1 border-b border-[var(--line)] group-hover:border-[var(--text-primary)] transition-colors flex items-center gap-2">
                  {copied ? (
                    <>
                      <CheckIcon className="w-3.5 h-3.5" />
                      Скопировано
                    </>
                  ) : (
                    <>
                      <ShareIcon className="w-3.5 h-3.5" />
                      Поделиться
                    </>
                  )}
                </span>
              </button>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ============ EPISODES ============ */}
      {(media.episodes?.length ?? 0) > 0 && (
        <section
          aria-labelledby="episodes-heading"
          className="border-t border-[var(--line)] bg-[var(--bg-secondary)]"
        >
          <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
            <div className="grid lg:grid-cols-12 gap-10 lg:gap-14">
              <div className="lg:col-span-3">
                <p
                  id="episodes-heading"
                  className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] lg:sticky lg:top-24"
                >
                  Эпизоды · {media.episodes!.length}
                </p>
              </div>
              <div className="lg:col-span-9">
                <h2 className="sr-only">Эпизоды</h2>
                <EpisodeList episodes={media.episodes!} />
              </div>
            </div>
          </div>
        </section>
      )}

      {/* ============ CREDITS ============ */}
      <section
        aria-labelledby="credits-heading"
        className="border-t border-[var(--line)]"
      >
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
          <div className="grid lg:grid-cols-12 gap-10 lg:gap-14">
            <div className="lg:col-span-3">
              <p
                id="credits-heading"
                className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] lg:sticky lg:top-24"
              >
                Съёмочная группа
              </p>
            </div>
            <div className="lg:col-span-9">
              <h2 className="sr-only">Съёмочная группа</h2>
              <CreditsList persons={media.persons} companies={media.companies} />
            </div>
          </div>
        </div>
      </section>

      {/* ============ SIMILAR ============ */}
      {showSimilar && (
        <section
          aria-labelledby="similar-heading"
          className="border-t border-[var(--line)] bg-[var(--bg-secondary)]"
        >
          <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
            <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-6 mb-12 lg:mb-16">
              <div>
                <p
                  id="similar-heading"
                  className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-5"
                >
                  Смотрите также
                </p>
                <h2 className="font-serif text-3xl sm:text-4xl lg:text-5xl leading-[0.92] tracking-[-0.025em]">
                  Похожее кино
                </h2>
              </div>
            </div>

            {similarState === 'loading' ? (
              <SimilarSkeleton />
            ) : similarData ? (
              <DirectorMovies data={similarData} />
            ) : null}
          </div>
        </section>
      )}

      {/* ============ МОДАЛКИ ============ */}
      {isEntryModalOpen && (
        <EntryForm
          mediaId={media.id}
          mediaTitle={media.title_ru}
          existingEntry={userEntry}
          onClose={() => setIsEntryModalOpen(false)}
          onSuccess={handleEntrySaved}
        />
      )}
      {showListModal && (
        <AddToListModal
          mediaId={media.id}
          mediaTitle={media.title_ru}
          onClose={() => setShowListModal(false)}
        />
      )}
    </div>
  );
}

/* ---------- Skeleton для похожих ---------- */

function SimilarSkeleton() {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 lg:gap-x-5 lg:gap-y-0 items-start animate-pulse">
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className={i % 2 === 1 ? 'lg:mt-12' : ''}>
          <div className="aspect-[2/3] rounded-[2px] bg-[var(--bg-tertiary)]" />
          <div className="h-4 w-4/5 bg-[var(--bg-tertiary)] rounded mt-4" />
          <div className="h-2.5 w-1/3 bg-[var(--bg-tertiary)] rounded mt-2" />
        </div>
      ))}
    </div>
  );
}

/* ---------- Описание ---------- */

function Description({ text }: { text: string }) {
  const [expanded, setExpanded] = useState(false);
  const needsExpand = text.length > 300;

  return (
    <div>
      <p
        className={`font-serif text-lg sm:text-xl leading-[1.55] text-[var(--text-primary)] whitespace-pre-line ${
          !expanded && needsExpand ? 'line-clamp-4' : ''
        }`}
      >
        {text}
      </p>
      {needsExpand && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="mt-4 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border-b border-[var(--line)] hover:border-[var(--text-primary)] pb-0.5 transition-colors"
        >
          {expanded ? 'Свернуть' : 'Читать далее'}
        </button>
      )}
    </div>
  );
}

/* ---------- Skeleton страницы ---------- */

function MediaSkeleton() {
  return (
    <div className="min-h-screen bg-[var(--bg-primary)]">
      <section className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center gap-3 pb-5 border-b border-[var(--line)] animate-pulse">
            <div className="h-2.5 w-20 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-2.5 w-16 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-2.5 w-40 bg-[var(--bg-tertiary)] rounded" />
          </div>
        </div>
      </section>

      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-16 lg:pb-24 animate-pulse">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-14">
          <div className="lg:col-span-4 xl:col-span-3">
            <div className="mx-auto lg:mx-0 w-full max-w-[280px] lg:max-w-none aspect-[2/3] rounded-[2px] bg-[var(--bg-tertiary)]" />
            <div className="mt-6 space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="h-6 bg-[var(--bg-tertiary)] rounded" />
              ))}
            </div>
          </div>
          <div className="lg:col-span-8 xl:col-span-9 space-y-6">
            <div className="h-3 w-32 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-20 w-full bg-[var(--bg-tertiary)] rounded" />
            <div className="h-6 w-1/2 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-3 w-1/3 bg-[var(--bg-tertiary)] rounded mt-8" />
            <div className="space-y-2 mt-6">
              <div className="h-4 w-full bg-[var(--bg-tertiary)] rounded" />
              <div className="h-4 w-full bg-[var(--bg-tertiary)] rounded" />
              <div className="h-4 w-3/4 bg-[var(--bg-tertiary)] rounded" />
            </div>
            <div className="flex gap-8 pt-8 border-t border-[var(--line)] mt-12">
              <div className="h-11 w-32 bg-[var(--bg-tertiary)] rounded-full" />
              <div className="h-11 w-28 bg-[var(--bg-tertiary)] rounded-full" />
              <div className="h-11 w-28 bg-[var(--bg-tertiary)] rounded-full ml-auto" />
            </div>
          </div>
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
          Фильм не найден
        </h1>
        <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
          Возможно, он был удалён или ссылка неверна. Попробуйте поискать в каталоге.
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
          Не удалось загрузить страницу
        </h1>
        <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
          Проверьте соединение с интернетом и попробуйте ещё раз.
        </p>
        <div className="mt-10 flex flex-wrap items-center justify-center gap-6">
          <button
            onClick={onRetry}
            className="group inline-flex items-center gap-3"
          >
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