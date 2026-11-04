// frontend/components/ui/GlobalSearch.tsx
'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Image from 'next/image';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { mediaApi, Media } from '@/lib/api/media';
import { resolveMediaUrl } from '@/lib/utils/media-url';
import {
  MagnifyingGlassIcon,
  FilmIcon,
  XMarkIcon,
  ArrowRightIcon,
  ArrowUpRightIcon,
} from '@heroicons/react/24/outline';

const MIN_QUERY = 2;
const DEBOUNCE_MS = 300;
const MAX_RESULTS = 5;

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

export default function GlobalSearch() {
  const router = useRouter();
  const prefersReduced = useReducedMotion();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<Media[]>([]);
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);

  const wrapperRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  const trimmed = query.trim();
  const tooShort = trimmed.length < MIN_QUERY;
  const showDropdown = isOpen && (isLoading || !tooShort);

  useEffect(() => {
    if (tooShort) {
      abortRef.current?.abort();
      abortRef.current = null;
      setResults([]);
      setIsOpen(false);
      setIsLoading(false);
      setActiveIndex(-1);
      return;
    }

    setIsLoading(true);
    const controller = new AbortController();
    abortRef.current = controller;

    const timer = setTimeout(async () => {
      try {
        const response = await mediaApi.getList({
          search: trimmed,
          limit: MAX_RESULTS,
        });
        if (controller.signal.aborted) return;
        setResults(response.data ?? []);
        setIsOpen(true);
        setActiveIndex(-1);
      } catch (err: any) {
        if (controller.signal.aborted || err?.name === 'AbortError') return;
        setResults([]);
      } finally {
        if (!controller.signal.aborted) setIsLoading(false);
      }
    }, DEBOUNCE_MS);

    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [trimmed, tooShort]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const isK = e.key.toLowerCase() === 'k';
      if ((e.metaKey || e.ctrlKey) && isK) {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    if (!isOpen) return;
    const onClick = (e: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setIsOpen(false);
        setActiveIndex(-1);
      }
    };
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, [isOpen]);

  const close = useCallback(() => {
    setIsOpen(false);
    setActiveIndex(-1);
  }, []);

  const clear = useCallback(() => {
    setQuery('');
    setResults([]);
    close();
    inputRef.current?.focus();
  }, [close]);

  const handleSelect = useCallback(
    (media: Media) => {
      setQuery('');
      setResults([]);
      close();
      inputRef.current?.blur();
      router.push(`/media/${media.id}`);
    },
    [router, close]
  );

  const goToAll = useCallback(() => {
    if (!trimmed) return;
    setQuery('');
    close();
    router.push(`/catalog?search=${encodeURIComponent(trimmed)}`);
  }, [trimmed, router, close]);

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      if (isOpen) {
        close();
      } else if (query) {
        clear();
      }
      return;
    }

    if (!isOpen) {
      if (e.key === 'ArrowDown' && !tooShort) {
        e.preventDefault();
        setIsOpen(true);
      }
      return;
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex((i) => (i < results.length - 1 ? i + 1 : i));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex((i) => (i > 0 ? i - 1 : -1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (activeIndex >= 0 && results[activeIndex]) {
        handleSelect(results[activeIndex]);
      } else if (results.length > 0) {
        goToAll();
      }
    }
  };

  useEffect(() => {
    if (activeIndex < 0) return;
    const el = document.getElementById(`search-result-${activeIndex}`);
    el?.scrollIntoView({ block: 'nearest' });
  }, [activeIndex]);

  const listId = 'global-search-results';

  return (
    <div className="relative w-full" ref={wrapperRef}>
      {/* ===== Input ===== */}
      <div className="relative flex items-center gap-2 border-b border-[var(--line)] focus-within:border-[var(--accent-yellow)] transition-colors duration-500">
        <MagnifyingGlassIcon
          className="w-3.5 h-3.5 shrink-0 text-[var(--text-muted)] pointer-events-none"
          aria-hidden="true"
        />
        <input
          ref={inputRef}
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKeyDown}
          onFocus={() => !tooShort && setIsOpen(true)}
          placeholder="Найти фильм или сериал…"
          autoComplete="off"
          spellCheck={false}
          role="combobox"
          aria-label="Глобальный поиск"
          aria-expanded={showDropdown}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={
            activeIndex >= 0 ? `search-result-${activeIndex}` : undefined
          }
          className="flex-1 min-w-0 bg-transparent border-0 outline-none py-2 font-mono text-[11px] uppercase tracking-[0.18em] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] placeholder:normal-case placeholder:tracking-normal placeholder:font-sans placeholder:text-sm placeholder:italic placeholder:opacity-70 [&::-webkit-search-cancel-button]:hidden"
        />

        <div className="shrink-0 flex items-center gap-1">
          {query ? (
            <button
              type="button"
              onClick={clear}
              aria-label="Очистить поиск"
              className="p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
            >
              <XMarkIcon className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          ) : (
            <kbd
              aria-hidden="true"
              className="hidden sm:inline-flex items-center px-1.5 h-5 text-[9px] font-mono tracking-[0.1em] text-[var(--text-muted)] border border-[var(--line)]"
            >
              ⌘K
            </kbd>
          )}
        </div>
      </div>

      {/* ===== Dropdown ===== */}
      <AnimatePresence>
        {showDropdown && (
          <motion.div
            initial={prefersReduced ? false : { opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={prefersReduced ? undefined : { opacity: 0, y: -4 }}
            transition={{ duration: 0.3, ease: EASE_OUT }}
            className="absolute top-full left-0 right-0 mt-2 bg-[var(--bg-primary)] border border-[var(--line)] z-[60] overflow-hidden"
          >
            {isLoading ? (
              <SearchSkeleton />
            ) : results.length === 0 ? (
              <div className="px-4 py-8 text-center">
                <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-2">
                  Ничего не найдено
                </p>
                <p className="font-serif italic text-sm text-[var(--text-secondary)]">
                  Попробуйте изменить запрос
                </p>
              </div>
            ) : (
              <>
                <ul
                  id={listId}
                  role="listbox"
                  className="max-h-80 overflow-y-auto"
                >
                  {results.map((media, i) => {
                    const poster = resolveMediaUrl(media.poster_url);
                    const year = media.release_date
                      ? new Date(media.release_date).getFullYear()
                      : null;
                    const active = activeIndex === i;

                    return (
                      <li
                        key={media.id}
                        id={`search-result-${i}`}
                        role="option"
                        aria-selected={active}
                        className="border-b border-[var(--line)] last:border-0"
                      >
                        <button
                          type="button"
                          onMouseEnter={() => setActiveIndex(i)}
                          onClick={() => handleSelect(media)}
                          className={`group w-full flex items-center gap-3 px-3 py-3 text-left transition-colors duration-300 ${
                            active ? 'bg-[var(--bg-secondary)]' : 'hover:bg-[var(--bg-secondary)]/60'
                          }`}
                        >
                          <span className="hidden sm:block font-mono text-[9px] tracking-[0.2em] text-[var(--text-muted)] min-w-[20px]">
                            {String(i + 1).padStart(2, '0')}
                          </span>

                          <div className="w-9 h-12 shrink-0 bg-[var(--bg-tertiary)] overflow-hidden">
                            {poster ? (
                              <Image
                                src={resolveMediaUrl(poster)!}
                                alt=""
                                fill
                                sizes="(max-width: 640px) 64px, 80px"
                                className="object-cover transition-transform duration-700 ease-[cubic-bezier(0.76,0,0.24,1)] group-hover:scale-[1.06]"
                              />
                            ) : (
                              <div className="w-full h-full grid place-items-center">
                                <FilmIcon
                                  className="w-4 h-4 text-[var(--text-muted)] opacity-40"
                                  aria-hidden="true"
                                />
                              </div>
                            )}
                          </div>

                          <div className="flex-1 min-w-0">
                            <p className="font-serif text-sm leading-tight text-[var(--text-primary)] truncate group-hover:italic transition-[font-style] duration-300">
                              {media.title_ru || 'Без названия'}
                            </p>
                            <p className="mt-1 font-mono text-[9px] uppercase tracking-[0.18em] text-[var(--text-muted)] truncate">
                              {[media.type?.name_ru, year]
                                .filter(Boolean)
                                .join(' · ')}
                            </p>
                          </div>

                          <ArrowUpRightIcon
                            className="w-3 h-3 shrink-0 text-[var(--text-muted)] opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                            aria-hidden="true"
                          />
                        </button>
                      </li>
                    );
                  })}
                </ul>

                <button
                  type="button"
                  onClick={goToAll}
                  className="group w-full flex items-center justify-between gap-3 px-4 py-3 border-t border-[var(--line)] hover:bg-[var(--bg-secondary)] transition-colors"
                >
                  <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors truncate">
                    Все результаты · «{trimmed}»
                  </span>
                  <ArrowRightIcon
                    className="w-3.5 h-3.5 shrink-0 text-[var(--text-muted)] transition-transform duration-500 group-hover:translate-x-0.5 group-hover:text-[var(--text-primary)]"
                    aria-hidden="true"
                  />
                </button>
              </>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/* ---------- Skeleton ---------- */

function SearchSkeleton() {
  return (
    <ul className="animate-pulse" aria-hidden="true">
      {[0, 1, 2].map((i) => (
        <li
          key={i}
          className="flex items-center gap-3 px-3 py-3 border-b border-[var(--line)] last:border-0"
        >
          <div className="hidden sm:block w-5 h-2 bg-[var(--bg-tertiary)]" />
          <div className="w-9 h-12 bg-[var(--bg-tertiary)] shrink-0" />
          <div className="flex-1 space-y-2">
            <div className="h-3 w-2/3 bg-[var(--bg-tertiary)]" />
            <div className="h-2 w-1/3 bg-[var(--bg-tertiary)]" />
          </div>
        </li>
      ))}
    </ul>
  );
}