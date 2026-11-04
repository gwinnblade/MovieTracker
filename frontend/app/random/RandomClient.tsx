'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import Link from 'next/link';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { mediaApi, Media } from '@/lib/api/media';
import { entriesApi, Entry, STATUS_MAP } from '@/lib/api/entries';
import EntryForm from '@/components/ui/EntryForm';
import AddToListModal from '@/components/ui/AddToListModal';
import toast from 'react-hot-toast';
import {
  FilmIcon,
  ArrowPathIcon,
  ArrowRightIcon,
  ArrowUpRightIcon,
  SparklesIcon,
  StarIcon,
  ListBulletIcon,
} from '@heroicons/react/24/outline';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const EASE_EDITORIAL = [0.76, 0, 0.24, 1] as const;

const HISTORY_LIMIT = 6;

export default function RandomClient() {
  const prefersReduced = useReducedMotion();
  const [media, setMedia] = useState<Media | null>(null);
  const [userEntry, setUserEntry] = useState<Entry | null>(null);
  const [rerolling, setRerolling] = useState(true);
  const [error, setError] = useState(false);
  const [isEntryModalOpen, setIsEntryModalOpen] = useState(false);
  const [showListModal, setShowListModal] = useState(false);
  const [history, setHistory] = useState<Media[]>([]);

  const mediaRef = useRef<Media | null>(null);
  const didInitRef = useRef(false);

  useEffect(() => {
    mediaRef.current = media;
  }, [media]);

  const fetchEntryFor = useCallback(async (mediaId: number): Promise<Entry | null> => {
    try {
      const entries = await entriesApi.getList();
      return Array.isArray(entries)
        ? entries.find((e: Entry) => e.media_id === mediaId) ?? null
        : null;
    } catch {
      return null;
    }
  }, []);

  const fetchRandom = useCallback(async () => {
    setRerolling(true);
    setError(false);
    try {
      const data = await mediaApi.getRandom();
      const entry = await fetchEntryFor(data.id);

      if (mediaRef.current) {
        setHistory((h) => [mediaRef.current!, ...h].slice(0, HISTORY_LIMIT));
      }
      setMedia(data);
      setUserEntry(entry);
    } catch (e) {
      console.error(e);
      setError(true);
      toast.error('Не удалось подобрать фильм');
    } finally {
      setRerolling(false);
    }
  }, [fetchEntryFor]);

  useEffect(() => {
    if (didInitRef.current) return;
    didInitRef.current = true;
    fetchRandom();
  }, [fetchRandom]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.code !== 'Space' || e.repeat) return;
      if (isEntryModalOpen || showListModal || rerolling) return;

      const target = e.target as HTMLElement;
      const interactive = target.closest(
        'button, a, input, textarea, select, [contenteditable="true"], [role="button"]'
      );
      if (interactive) return;

      e.preventDefault();
      fetchRandom();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [fetchRandom, isEntryModalOpen, showListModal, rerolling]);

  const handleEntrySaved = async () => {
    if (!media) return;
    setIsEntryModalOpen(false);
    const entry = await fetchEntryFor(media.id);
    setUserEntry(entry);
    toast.success('Отметка сохранена');
  };

  const restoreFromHistory = async (m: Media) => {
    if (!media || m.id === media.id) return;
    setHistory((h) => [media, ...h.filter((x) => x.id !== m.id)].slice(0, HISTORY_LIMIT));
    setMedia(m);
    setUserEntry(await fetchEntryFor(m.id));
  };

  const hasMedia = !!media;

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      {/* ============ MASTHEAD ============ */}
      <section className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
            <span className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-yellow)]" />
              Случайный выбор
            </span>
            <span className="hidden sm:inline">MovieTracker · Рулетка</span>
          </div>
        </div>

        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-14 lg:pb-20">
          <motion.div
            initial={prefersReduced ? false : { opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 1, ease: EASE_OUT }}
          >
            <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
              Не знаете, что посмотреть?
            </p>
            <h1 className="font-serif text-[clamp(2.75rem,10vw,8rem)] leading-[0.84] tracking-[-0.045em]">
              Подберём
              <br />
              <span className="italic">за вас</span>
              <span className="text-[var(--accent-yellow)]">.</span>
            </h1>
            <p className="mt-8 max-w-xl text-base sm:text-lg text-[var(--text-secondary)] leading-relaxed">
              Подберём случайный фильм, сериал или аниме из нашего каталога
            </p>
          </motion.div>
        </div>
      </section>

      {/* ============ RESULT ============ */}
      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
        <AnimatePresence mode="wait" initial={false}>
          {media ? (
            <motion.div
              key={media.id}
              initial={prefersReduced ? false : { opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={prefersReduced ? undefined : { opacity: 0, y: -12 }}
              transition={{ duration: 0.6, ease: EASE_OUT }}
            >
              <RandomFeature
                media={media}
                userEntry={userEntry}
                dimmed={rerolling}
                onOpenEntry={() => setIsEntryModalOpen(true)}
                onAddToList={() => setShowListModal(true)}
              />
            </motion.div>
          ) : error ? (
            <motion.div
              key="error"
              initial={prefersReduced ? false : { opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={prefersReduced ? undefined : { opacity: 0, y: -16 }}
              transition={{ duration: 0.4, ease: EASE_OUT }}
            >
              <ErrorState onRetry={fetchRandom} />
            </motion.div>
          ) : (
            <motion.div
              key="skeleton"
              exit={prefersReduced ? undefined : { opacity: 0 }}
              transition={{ duration: 0.2 }}
            >
              <RandomSkeleton />
            </motion.div>
          )}
        </AnimatePresence>

        {/* ============ REROLL ============ */}
        <div className="mt-14 lg:mt-20 flex flex-col items-center gap-5">
          <button
            onClick={fetchRandom}
            disabled={rerolling}
            className="group inline-flex items-center gap-5 pl-6 pr-2 py-2 border border-[var(--text-primary)] disabled:opacity-40 disabled:cursor-not-allowed hover:bg-[var(--text-primary)] hover:text-[var(--bg-primary)] transition-colors duration-500"
          >
            <span className="font-mono text-[11px] uppercase tracking-[0.25em]">
              {rerolling
                ? 'Ищем…'
                : hasMedia
                  ? 'Другой вариант'
                  : 'Найти случайное'}
            </span>
            <span className="w-10 h-10 rounded-full grid place-items-center bg-[var(--text-primary)] text-[var(--bg-primary)] group-hover:bg-[var(--bg-primary)] group-hover:text-[var(--text-primary)] transition-colors duration-500">
              {rerolling ? (
                <ArrowPathIcon className="w-4 h-4 animate-spin" />
              ) : hasMedia ? (
                <ArrowPathIcon className="w-4 h-4" />
              ) : (
                <SparklesIcon className="w-4 h-4" />
              )}
            </span>
          </button>

          {hasMedia && (
            <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] flex items-center gap-2">
              <kbd className="px-2 py-0.5 border border-[var(--line)] text-[10px] font-mono">
                пробел
              </kbd>
              <span>— тоже подобрать</span>
            </p>
          )}
        </div>

        {/* ============ HISTORY ============ */}
        {history.length > 0 && (
          <motion.div
            className="mt-20 lg:mt-28 pt-10 border-t border-[var(--line)]"
            initial={prefersReduced ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.15 }}
          >
            <div className="flex items-baseline justify-between mb-8">
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                Недавно выпадало
              </p>
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                {String(history.length).padStart(2, '0')}
              </p>
            </div>

            <div className="flex gap-3 lg:gap-4 overflow-x-auto pb-2 -mx-1 px-1 snap-x">
              {history.map((m) => (
                <button
                  key={m.id}
                  onClick={() => restoreFromHistory(m)}
                  className="shrink-0 w-20 sm:w-24 group text-left snap-start"
                  title={`Вернуться к «${m.title_ru}»`}
                >
                  <div className="relative aspect-[2/3] overflow-hidden rounded-[2px] bg-[var(--bg-tertiary)]">
                    {m.poster_url ? (
                      <img
                        src={m.poster_url}
                        alt=""
                        loading="lazy"
                        className="w-full h-full object-cover transition-transform duration-[1200ms] ease-[cubic-bezier(0.76,0,0.24,1)] group-hover:scale-[1.08]"
                      />
                    ) : (
                      <div className="w-full h-full grid place-items-center text-[var(--text-muted)]">
                        <FilmIcon className="w-6 h-6 opacity-40" />
                      </div>
                    )}
                    <span className="pointer-events-none absolute inset-1 border border-transparent group-hover:border-[var(--accent-yellow)]/70 transition-colors duration-500" />
                    <span className="absolute inset-0 bg-black/0 group-hover:bg-black/20 transition-colors duration-500" />
                  </div>
                  <p className="mt-2 font-mono text-[9px] uppercase tracking-[0.15em] text-[var(--text-muted)] truncate">
                    {m.title_ru}
                  </p>
                </button>
              ))}
            </div>
          </motion.div>
        )}
      </section>

      {/* ============ МОДАЛКИ ============ */}
      {isEntryModalOpen && media && (
        <EntryForm
          mediaId={media.id}
          mediaTitle={media.title_ru}
          existingEntry={userEntry}
          onClose={() => setIsEntryModalOpen(false)}
          onSuccess={handleEntrySaved}
        />
      )}
      {showListModal && media && (
        <AddToListModal
          mediaId={media.id}
          mediaTitle={media.title_ru}
          onClose={() => setShowListModal(false)}
        />
      )}
    </div>
  );
}

/* ---------- Карточка-фича (hero-result) ---------- */

function RandomFeature({
  media,
  userEntry,
  dimmed,
  onOpenEntry,
  onAddToList,
}: {
  media: Media;
  userEntry: Entry | null;
  dimmed: boolean;
  onOpenEntry: () => void;
  onAddToList: () => void;
}) {
  const [expanded, setExpanded] = useState(false);

  const status = userEntry ? STATUS_MAP[userEntry.status_id] : null;
  const year = media.release_date ? new Date(media.release_date).getFullYear() : null;
  const description = media.description_ru ?? '';
  const needsExpand = description.length > 280;

  return (
    <div
      className={`grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-14 transition-opacity duration-300 ${
        dimmed ? 'opacity-50 pointer-events-none select-none' : ''
      }`}
    >
      {/* Постер */}
      <div className="lg:col-span-4 xl:col-span-3">
        <div className="relative mx-auto lg:mx-0 w-full max-w-[280px] lg:max-w-none aspect-[2/3] overflow-hidden rounded-[2px] bg-[var(--bg-tertiary)]">
          {media.poster_url ? (
            <img
              src={media.poster_url}
              alt={media.title_ru}
              className="w-full h-full object-cover"
            />
          ) : (
            <div className="w-full h-full grid place-items-center text-[var(--text-muted)]">
              <FilmIcon className="w-14 h-14 opacity-25" />
            </div>
          )}
          <span className="pointer-events-none absolute inset-3 border border-white/10" />
        </div>
      </div>

      {/* Инфо */}
      <div className="lg:col-span-8 xl:col-span-9 min-w-0 flex flex-col">
        {/* Мета */}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 mb-6 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
          {media.type && (
            <span className="inline-flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-yellow)]" />
              <span className="text-[var(--text-secondary)]">{media.type.name_ru}</span>
            </span>
          )}
          {year && <span className="tabular-nums">{year}</span>}
          {status && (
            <span className="inline-flex items-center gap-2">
              <span className="text-[var(--text-muted)]/50">·</span>
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{ background: `var(--accent-${status.color})` }}
              />
              <span>{status.name}</span>
              {userEntry?.rating ? (
                <span className="text-[var(--text-secondary)] tabular-nums">
                  · {userEntry.rating}/10
                </span>
              ) : null}
            </span>
          )}
        </div>

        {/* Название */}
        <h2 className="font-serif text-[clamp(2rem,5.5vw,4.5rem)] leading-[0.9] tracking-[-0.035em] break-words">
          {media.title_ru}
          <span className="text-[var(--accent-yellow)]">.</span>
        </h2>
        {media.title_en && (
          <p className="mt-4 font-serif italic text-lg sm:text-xl text-[var(--text-secondary)] tracking-[-0.005em]">
            {media.title_en}
          </p>
        )}

        {/* Жанры */}
        {(media.genres?.length ?? 0) > 0 && (
          <div className="mt-8 flex flex-wrap gap-x-4 gap-y-2">
            {media.genres!.map((g, i) => (
              <span key={g.id} className="inline-flex items-center gap-4">
                {i > 0 && <span className="text-[var(--text-muted)]/40">·</span>}
                <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-secondary)]">
                  {g.name_ru}
                </span>
              </span>
            ))}
          </div>
        )}

        {/* Описание */}
        {description ? (
          <div className="mt-10 max-w-2xl">
            <p
              className={`font-serif text-base sm:text-lg leading-[1.55] text-[var(--text-primary)] ${
                !expanded && needsExpand ? 'line-clamp-4' : ''
              }`}
            >
              {description}
            </p>
            {needsExpand && (
              <button
                onClick={() => setExpanded((v) => !v)}
                className="mt-4 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border-b border-[var(--line)] hover:border-[var(--text-primary)] pb-0.5 transition-colors"
              >
                {expanded ? 'Свернуть' : 'Читать далее'}
              </button>
            )}
          </div>
        ) : (
          <p className="mt-10 text-sm italic text-[var(--text-muted)]">
            Описание пока не добавлено
          </p>
        )}

        {/* Действия */}
        <div className="mt-12 pt-8 border-t border-[var(--line)] flex flex-wrap items-center gap-x-8 gap-y-4">
          <button onClick={onOpenEntry} className="group inline-flex items-center gap-3">
            <span className="w-11 h-11 rounded-full bg-[var(--text-primary)] text-[var(--bg-primary)] grid place-items-center transition-transform duration-500 group-hover:rotate-[-8deg] group-hover:scale-105">
              <StarIcon className="w-5 h-5" />
            </span>
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
              {userEntry ? 'Изменить отметку' : 'Отметить'}
            </span>
          </button>

          <button onClick={onAddToList} className="group inline-flex items-center gap-3">
            <span className="w-11 h-11 rounded-full border border-[var(--line)] grid place-items-center transition-colors duration-300 group-hover:border-[var(--text-primary)]">
              <ListBulletIcon className="w-5 h-5" />
            </span>
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
              В список
            </span>
          </button>

          <Link
            href={`/media/${media.id}`}
            className="group inline-flex items-center gap-3 ml-auto"
          >
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
              Подробнее
            </span>
            <span className="w-10 h-10 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
              <ArrowUpRightIcon className="w-4 h-4 transition-transform duration-500 group-hover:rotate-45" />
            </span>
          </Link>
        </div>
      </div>
    </div>
  );
}

/* ---------- Skeleton ---------- */

function RandomSkeleton() {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-14 animate-pulse">
      <div className="lg:col-span-4 xl:col-span-3">
        <div className="mx-auto lg:mx-0 w-full max-w-[280px] lg:max-w-none aspect-[2/3] rounded-[2px] bg-[var(--bg-tertiary)]" />
      </div>
      <div className="lg:col-span-8 xl:col-span-9 space-y-4">
        <div className="h-2.5 w-40 bg-[var(--bg-tertiary)] rounded" />
        <div className="h-20 w-3/4 bg-[var(--bg-tertiary)] rounded" />
        <div className="h-6 w-1/2 bg-[var(--bg-tertiary)] rounded" />
        <div className="space-y-2 mt-8">
          <div className="h-3 w-full bg-[var(--bg-tertiary)] rounded" />
          <div className="h-3 w-full bg-[var(--bg-tertiary)] rounded" />
          <div className="h-3 w-3/4 bg-[var(--bg-tertiary)] rounded" />
        </div>
        <div className="flex gap-8 pt-8 border-t border-[var(--line)] mt-10">
          <div className="h-11 w-32 bg-[var(--bg-tertiary)] rounded-full" />
          <div className="h-11 w-28 bg-[var(--bg-tertiary)] rounded-full" />
          <div className="h-11 w-28 bg-[var(--bg-tertiary)] rounded-full ml-auto" />
        </div>
      </div>
    </div>
  );
}

/* ---------- Error ---------- */

function ErrorState({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="py-20 lg:py-28 text-center border-y border-[var(--line)]">
      <div className="inline-flex items-center gap-2 mb-6">
        <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-red)]" />
        <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--accent-red)]">
          Ошибка
        </p>
      </div>
      <h2 className="font-serif text-4xl sm:text-5xl tracking-[-0.02em] mb-4">
        Не удалось подобрать фильм
      </h2>
      <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
        Что-то пошло не так на нашей стороне. Попробуйте ещё раз.
      </p>
      <div className="mt-10 flex justify-center">
        <button onClick={onRetry} className="group inline-flex items-center gap-3">
          <span className="w-11 h-11 rounded-full bg-[var(--text-primary)] text-[var(--bg-primary)] grid place-items-center transition-transform duration-500 group-hover:rotate-[-8deg] group-hover:scale-105">
            <ArrowPathIcon className="w-5 h-5" />
          </span>
          <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-primary)] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
            Попробовать снова
          </span>
        </button>
      </div>
    </div>
  );
}