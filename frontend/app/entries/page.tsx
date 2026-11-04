'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import { resolveMediaUrl } from '@/lib/utils/media-url';
import { motion, useReducedMotion } from 'framer-motion';
import { entriesApi, Entry, STATUS_MAP } from '@/lib/api/entries';
import {
  TrashIcon,
  FilmIcon,
  ChevronLeftIcon,
  CalendarDaysIcon,
  ArrowRightIcon,
} from '@heroicons/react/24/outline';
import { StarIcon as StarSolid } from '@heroicons/react/24/solid';
import toast from 'react-hot-toast';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

function formatDate(iso: string) {
  const d = new Date(iso);
  const now = new Date();
  const days = Math.floor((now.getTime() - d.getTime()) / 86_400_000);
  if (days === 0) return 'Сегодня';
  if (days === 1) return 'Вчера';
  if (days > 1 && days < 7) return `${days} дн. назад`;
  return d.toLocaleDateString('ru-RU', { day: 'numeric', month: 'long' });
}

export default function EntriesPage() {
  const prefersReduced = useReducedMotion();
  const [entries, setEntries] = useState<Entry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<number | null>(null);

  const fetchEntries = async () => {
    try {
      setLoading(true);
      const data = await entriesApi.getList();
      setEntries(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Ошибка загрузки отметок:', error);
      toast.error('Не удалось загрузить отметки');
      setEntries([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEntries();
  }, []);

  const counts = useMemo(() => {
    const c: Record<number, number> = {};
    for (const e of entries) c[e.status_id] = (c[e.status_id] || 0) + 1;
    return c;
  }, [entries]);

  const filtered = useMemo(
    () => (filter === null ? entries : entries.filter((e) => e.status_id === filter)),
    [entries, filter]
  );

  const confirmDelete = (entry: Entry) => {
    const title = entry.media?.title_ru ?? 'эту отметку';
    toast(
      (t) => (
        <span className="flex items-center gap-3 text-sm">
          <span className="text-[var(--text-primary)]">Удалить «{title}»?</span>
          <button
            onClick={() => {
              toast.dismiss(t.id);
              doDelete(entry.id);
            }}
            className="font-semibold text-[var(--accent-red)] hover:underline"
          >
            Удалить
          </button>
          <button
            onClick={() => toast.dismiss(t.id)}
            className="text-[var(--text-muted)] hover:underline"
          >
            Отмена
          </button>
        </span>
      ),
      { duration: 6000 }
    );
  };

  const doDelete = async (entryId: number) => {
    const snapshot = entries;
    setEntries((prev) => prev.filter((e) => e.id !== entryId));
    try {
      await entriesApi.delete(entryId);
      toast.success('Отметка удалена');
    } catch {
      setEntries(snapshot);
      toast.error('Не удалось удалить');
    }
  };

  const totalCount = entries.length;
  const shownCount = filtered.length;

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      {/* ============ MASTHEAD ============ */}
      <section className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
            <Link
              href="/catalog"
              className="group inline-flex items-center gap-2 hover:text-[var(--text-primary)] transition-colors"
            >
              <ChevronLeftIcon className="w-3.5 h-3.5 transition-transform group-hover:-translate-x-0.5" />
              <span>К каталогу</span>
            </Link>
            <span className="hidden sm:inline">
              Дневник · {totalCount}{' '}
              {totalCount === 1 ? 'запись' : totalCount < 5 ? 'записи' : 'записей'}
            </span>
          </div>
        </div>

        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-14 lg:pb-20">
          <motion.div
            initial={prefersReduced ? false : { opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, ease: EASE_OUT }}
          >
            <h1 className="font-serif text-[clamp(3.5rem,14vw,12rem)] leading-[0.82] tracking-[-0.045em]">
              Мои отметки<span className="text-[var(--accent-yellow)]">.</span>
            </h1>
            <div className="mt-8 lg:mt-10 flex flex-col sm:flex-row sm:items-end sm:justify-between gap-6">
              <p className="max-w-md text-base sm:text-lg text-[var(--text-secondary)] leading-relaxed">
                {totalCount === 0
                  ? 'Пока ничего не отмечено'
                  : `${totalCount} ${
                      totalCount === 1 ? 'запись' : totalCount < 5 ? 'записи' : 'записей'
                    } в дневнике`}
              </p>
              <Link
                href="/catalog"
                className="group inline-flex items-center gap-3 self-start sm:self-end"
              >
                <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
                  Добавить фильм
                </span>
                <span className="w-10 h-10 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
                  <ArrowRightIcon className="w-4 h-4 transition-transform duration-500 group-hover:translate-x-0.5" />
                </span>
              </Link>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ============ FILTERS ============ */}
      <section className="border-b border-[var(--line)] bg-[var(--bg-secondary)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10">
          <div className="flex flex-wrap items-center gap-x-8 gap-y-2 py-5 lg:py-6">
            <FilterTab
              active={filter === null}
              onClick={() => setFilter(null)}
              label="Все"
              count={totalCount}
            />
            {Object.entries(STATUS_MAP).map(([id, info]) => {
              const n = Number(id);
              return (
                <FilterTab
                  key={id}
                  active={filter === n}
                  onClick={() => setFilter(n)}
                  label={info.name}
                  count={counts[n] ?? 0}
                  accent={info.color}
                />
              );
            })}
          </div>
        </div>
      </section>

      {/* ============ LIST ============ */}
      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 py-12 lg:py-16">
        {loading ? (
          <SkeletonList />
        ) : shownCount === 0 ? (
          <EmptyState filtered={filter !== null} onReset={() => setFilter(null)} />
        ) : (
          <>
            <div className="flex items-center justify-between pb-3 border-b border-[var(--line)]">
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                {filter === null ? 'Все записи' : `Показано ${shownCount} из ${totalCount}`}
              </p>
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                {new Date().getFullYear()}
              </p>
            </div>

            <ul>
              {filtered.map((entry, i) => (
                <motion.li
                  key={entry.id}
                  initial={prefersReduced ? false : { opacity: 0, y: 14 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{
                    duration: 0.55,
                    delay: Math.min(i * 0.04, 0.35),
                    ease: EASE_OUT,
                  }}
                  className="border-b border-[var(--line)]"
                >
                  <EntryRow
                    entry={entry}
                    index={i}
                    onDelete={() => confirmDelete(entry)}
                  />
                </motion.li>
              ))}
            </ul>
          </>
        )}
      </section>
    </div>
  );
}

/* ---------- Таб-фильтр ---------- */

function FilterTab({
  active,
  onClick,
  label,
  count,
  accent,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  count: number;
  accent?: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`group relative flex items-baseline gap-2 pb-1.5 transition-colors ${
        active
          ? 'text-[var(--text-primary)]'
          : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)]'
      }`}
    >
      {accent && (
        <span
          className="w-1.5 h-1.5 rounded-full mb-0.5 shrink-0"
          style={{
            background: `var(--accent-${accent})`,
            opacity: active ? 1 : 0.45,
          }}
        />
      )}
      <span className="font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.2em]">
        {label}
      </span>
      <span className="font-serif italic text-sm tabular-nums opacity-60">
        {count}
      </span>
      {active && (
        <span
          className="absolute -bottom-[1px] left-0 right-0 h-[1.5px]"
          style={{
            background: accent ? `var(--accent-${accent})` : 'var(--text-primary)',
          }}
        />
      )}
    </button>
  );
}

/* ---------- Строка записи ---------- */

function EntryRow({
  entry,
  index,
  onDelete,
}: {
  entry: Entry;
  index: number;
  onDelete: () => void;
}) {
  const status = STATUS_MAP[entry.status_id];
  const year = entry.media?.release_date
    ? new Date(entry.media.release_date).getFullYear()
    : null;

  return (
    <div className="relative group">
      <Link
        href={`/media/${entry.media_id}`}
        className="grid grid-cols-[auto_1fr_auto] items-start gap-4 sm:gap-6 lg:gap-8 py-6 lg:py-8 pr-10 sm:pr-14"
      >
        {/* Индекс */}
        <div className="hidden sm:block font-mono text-[10px] tracking-[0.2em] text-[var(--text-muted)] pt-2 min-w-[24px]">
          {String(index + 1).padStart(2, '0')}
        </div>

        {/* Постер */}
        <div className="relative shrink-0 w-16 sm:w-20 lg:w-[88px] aspect-[2/3] overflow-hidden rounded-[2px] bg-[var(--bg-tertiary)]">
          {entry.media?.poster_url && (
            <Image
              src={resolveMediaUrl(entry.media.poster_url)!}
              alt={entry.media?.title_ru || 'Постер'}
              fill
              sizes="(max-width: 768px) 120px, 160px"
              className="object-cover transition-transform duration-[1200ms] ease-[cubic-bezier(0.76,0,0.24,1)] group-hover:scale-[1.06]"
            />
          )}
          <div
            className="absolute inset-0 w-full h-full items-center justify-center text-[var(--text-muted)]"
            style={{ display: entry.media?.poster_url ? 'none' : 'flex' }}
          >
            <FilmIcon className="w-6 h-6 opacity-40" />
          </div>
          <span className="pointer-events-none absolute inset-1.5 border border-transparent group-hover:border-[var(--accent-yellow)]/60 transition-colors duration-500" />
        </div>

        {/* Контент */}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <h3 className="font-serif text-xl sm:text-2xl lg:text-3xl leading-tight tracking-[-0.01em] group-hover:italic transition-[font-style] duration-300">
              {entry.media?.title_ru || 'Без названия'}
            </h3>
            {year && (
              <span className="font-mono text-[11px] tabular-nums text-[var(--text-muted)]">
                {year}
              </span>
            )}
          </div>

          {entry.media?.type && (
            <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
              {entry.media.type.name_ru}
            </p>
          )}

          {entry.note && (
            <p className="mt-3 text-sm text-[var(--text-secondary)] line-clamp-2 max-w-xl leading-relaxed">
              {entry.note}
            </p>
          )}

          <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-xs">
            {status && (
              <span className="inline-flex items-center gap-2">
                <span
                  className="w-1.5 h-1.5 rounded-full"
                  style={{ background: `var(--accent-${status.color})` }}
                />
                <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)]">
                  {status.name}
                </span>
              </span>
            )}
            {entry.date && (
              <span className="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)]">
                <CalendarDaysIcon className="w-3 h-3" />
                {formatDate(entry.date)}
              </span>
            )}
          </div>
        </div>

        {/* Рейтинг */}
        <div className="text-right pt-1">
          {entry.rating ? (
            <div className="flex items-baseline justify-end gap-1.5">
              <StarSolid className="w-3 h-3 sm:w-3.5 sm:h-3.5 text-[var(--accent-yellow)] self-center" />
              <span className="font-serif text-2xl sm:text-3xl lg:text-4xl tracking-[-0.02em] tabular-nums">
                {entry.rating}
              </span>
              <span className="font-mono text-[10px] text-[var(--text-muted)]">/10</span>
            </div>
          ) : null}
        </div>
      </Link>

      <button
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          onDelete();
        }}
        aria-label="Удалить отметку"
        title="Удалить отметку"
        className="absolute top-6 right-0 sm:top-8 w-8 h-8 flex items-center justify-center text-[var(--text-muted)] opacity-0 group-hover:opacity-100 focus-visible:opacity-100 hover:text-[var(--accent-red)] transition-all"
      >
        <TrashIcon className="w-4 h-4" />
      </button>
    </div>
  );
}

/* ---------- Skeleton ---------- */

function SkeletonList() {
  return (
    <ul>
      {Array.from({ length: 4 }).map((_, i) => (
        <li
          key={i}
          className="grid grid-cols-[auto_1fr_auto] items-start gap-4 sm:gap-6 lg:gap-8 py-6 lg:py-8 border-b border-[var(--line)] animate-pulse"
        >
          <div className="hidden sm:block w-6 h-2 mt-3 bg-[var(--bg-tertiary)] rounded" />
          <div className="shrink-0 w-16 sm:w-20 lg:w-[88px] aspect-[2/3] bg-[var(--bg-tertiary)] rounded-[2px]" />
          <div className="flex-1 pt-1 space-y-3">
            <div className="h-5 w-2/3 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-2.5 w-1/4 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-3 w-full bg-[var(--bg-tertiary)] rounded" />
            <div className="h-2.5 w-1/3 bg-[var(--bg-tertiary)] rounded" />
          </div>
          <div className="w-14 h-8 bg-[var(--bg-tertiary)] rounded" />
        </li>
      ))}
    </ul>
  );
}

/* ---------- Пустой стейт ---------- */

function EmptyState({
  filtered,
  onReset,
}: {
  filtered: boolean;
  onReset: () => void;
}) {
  return (
    <div className="py-24 lg:py-32 text-center border-y border-[var(--line)]">
      <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
        {filtered ? 'Пусто по фильтру' : 'Нет записей'}
      </p>
      <h2 className="font-serif text-4xl sm:text-5xl tracking-[-0.02em] mb-4">
        {filtered ? 'Здесь пока пусто' : 'Дневник ждёт первую запись'}
      </h2>
      <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
        {filtered
          ? 'С этим статусом отметок нет. Попробуйте другой фильтр.'
          : 'Найдите фильм в каталоге и отметьте его — так вы начнёте собирать свою историю.'}
      </p>
      <div className="mt-10 flex justify-center">
        {filtered ? (
          <button
            onClick={onReset}
            className="inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-primary)] border-b border-[var(--text-primary)] pb-0.5 hover:border-[var(--accent-yellow)] transition-colors"
          >
            Сбросить фильтр
          </button>
        ) : (
          <Link href="/catalog" className="group inline-flex items-center gap-3">
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
              В каталог
            </span>
            <span className="w-10 h-10 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
              <ArrowRightIcon className="w-4 h-4 transition-transform duration-500 group-hover:translate-x-0.5" />
            </span>
          </Link>
        )}
      </div>
    </div>
  );
}
