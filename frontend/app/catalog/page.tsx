'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import Image from 'next/image';
import { resolveMediaUrl } from '@/lib/utils/media-url';
import { motion, useReducedMotion } from 'framer-motion';
import { mediaApi, Media } from '@/lib/api/media';
import { referenceApi, Type, Genre } from '@/lib/api/reference';
import Button from '@/components/ui/Button';
import {
  FilmIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ArrowRightIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline';
import { useAllReferences } from '@/hooks/useReferences';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const EASE_EDITORIAL = [0.76, 0, 0.24, 1] as const;

const STAGGER = ['', 'lg:mt-16', 'lg:mt-4', 'lg:mt-24', 'lg:mt-8', 'lg:mt-20'];

export default function CatalogPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const prefersReduced = useReducedMotion();

  const [yearFrom, setYearFrom] = useState(searchParams.get('year_from') || '');
  const [yearTo, setYearTo] = useState(searchParams.get('year_to') || '');
  const [selectedGenres, setSelectedGenres] = useState<string[]>(
    searchParams.get('genre_ids') ? searchParams.get('genre_ids')!.split(',') : []
  );
  const [sortBy, setSortBy] = useState(searchParams.get('sort_by') || 'release_date');
  const [sortOrder, setSortOrder] = useState(searchParams.get('sort_order') || 'desc');
  const [isGenreDropdownOpen, setIsGenreDropdownOpen] = useState(false);

  // Состояние фильтров (инициализируем из URL)
  const [search, setSearch] = useState(searchParams.get('search') || '');
  const [typeId, setTypeId] = useState(searchParams.get('type') || '');
  const [year, setYear] = useState(searchParams.get('year') || '');
  const [genreId, setGenreId] = useState(searchParams.get('genre') || '');
  const [page, setPage] = useState(Number(searchParams.get('page')) || 1);

  // Состояние данных
  const [mediaList, setMediaList] = useState<Media[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [types, setTypes] = useState<Type[]>([]);
  const [genres, setGenres] = useState<Genre[]>([]);
  const [loading, setLoading] = useState(true);

  const limit = 12;

  const currentPage = Number(searchParams.get('page')) || 1;
  const totalPages = Math.ceil(totalCount / limit);
  const { data: references, isLoading: referencesLoading } = useAllReferences();

  const updatePage = useCallback(
    (newPage: number) => {
      const params = new URLSearchParams(searchParams.toString());
      params.set('page', newPage.toString());
      router.push(`/catalog?${params.toString()}`);
    },
    [searchParams, router]
  );

  useEffect(() => {
    if (references) {
      setTypes(references.types);
      setGenres(references.genres);
    }
  }, [references]);

  const updateFilters = useCallback(
    (newFilters: Record<string, any>) => {
      const params = new URLSearchParams(searchParams.toString());

      ['search', 'type', 'year_from', 'year_to', 'genre_ids', 'sort_by', 'sort_order'].forEach((key) =>
        params.delete(key)
      );

      Object.entries(newFilters).forEach(([key, value]) => {
        if (value) {
          if (Array.isArray(value)) {
            params.set(key, value.join(','));
          } else {
            params.set(key, String(value));
          }
        }
      });

      params.set('page', '1');
      setPage(1);
      router.push(`/catalog?${params.toString()}`);
    },
    [searchParams, router]
  );

  // Обработчики изменений
  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setSearch(value);
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    updateFilters({
      search,
      type: typeId,
      year,
      genre: genreId,
    });
  };

  useEffect(() => {
    const fetchMedia = async () => {
      setLoading(true);
      try {
        const params: any = {
          page: searchParams.get('page') || 1,
          limit: 12,
        };

        const searchVal = searchParams.get('search');
        if (searchVal) params.search = searchVal;

        const typeVal = searchParams.get('type');
        if (typeVal) params.type_id = typeVal;

        const yearFromVal = searchParams.get('year_from');
        if (yearFromVal) params.year_from = yearFromVal;

        const yearToVal = searchParams.get('year_to');
        if (yearToVal) params.year_to = yearToVal;

        const genreVal = searchParams.get('genre_ids');
        if (genreVal) params.genre_ids = genreVal;

        const sortVal = searchParams.get('sort_by');
        if (sortVal) params.sort_by = sortVal;

        const orderVal = searchParams.get('sort_order');
        if (orderVal) params.sort_order = orderVal;

        const response = await mediaApi.getList(params);
        setMediaList(response.data || []);
        setTotalCount(response.total || 0);
      } catch (error) {
        console.error('Ошибка загрузки каталога:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchMedia();
  }, [searchParams]);

  const hasActiveFilters =
    !!search || !!typeId || !!yearFrom || !!yearTo || selectedGenres.length > 0;

  const handleReset = () => {
    setSearch('');
    setTypeId('');
    setYearFrom('');
    setYearTo('');
    setSelectedGenres([]);
    setSortBy('release_date');
    setSortOrder('desc');
    router.push('/catalog');
  };

  const fadeUp = prefersReduced
    ? {}
    : {
        initial: { opacity: 0, y: 24 },
        whileInView: { opacity: 1, y: 0 },
        viewport: { once: true, margin: '-60px' },
      };

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      {/* ============ HERO ============ */}
      <section className="relative border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
            <span>MovieTracker — Каталог</span>
            <span className="hidden sm:inline">
              {loading ? 'Загрузка…' : `${totalCount} записей`}
            </span>
          </div>
        </div>

        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-14 lg:pb-20">
          <h1 className="font-serif text-[clamp(4rem,15vw,13rem)] leading-[0.82] tracking-[-0.045em]">
            Каталог<span className="text-[var(--accent-yellow)]">.</span>
          </h1>
          <div className="mt-8 lg:mt-10 flex flex-col sm:flex-row sm:items-end sm:justify-between gap-6">
            <p className="max-w-md text-base sm:text-lg text-[var(--text-secondary)] leading-relaxed">
              Найдите свой следующий любимый фильм или сериал
            </p>
            <span className="font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
              {loading ? 'Идёт поиск…' : `Показано ${mediaList.length} из ${totalCount}`}
            </span>
          </div>
        </div>
      </section>

      {/* ============ ФИЛЬТРЫ ============ */}
      <section className="border-b border-[var(--line)] bg-[var(--bg-secondary)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10">
          {/* Строка поиска */}
          <form
            onSubmit={handleSearchSubmit}
            className="py-8 lg:py-10 flex items-center gap-4 border-b border-[var(--line)]"
          >
            <MagnifyingGlassIcon className="w-5 h-5 shrink-0 text-[var(--text-muted)]" />
            <input
              type="text"
              placeholder="Найти фильм или сериал…"
              value={search}
              onChange={handleSearchChange}
              className="flex-1 min-w-0 bg-transparent border-0 outline-none text-xl sm:text-2xl lg:text-3xl font-serif tracking-[-0.01em] placeholder:text-[var(--text-muted)] placeholder:italic placeholder:font-serif"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch('')}
                className="text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                aria-label="Очистить поиск"
              >
                <XMarkIcon className="w-4 h-4" />
              </button>
            )}
            <button
              type="submit"
              className="group inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
            >
              Найти
              <ArrowRightIcon className="w-4 h-4 transition-transform duration-500 group-hover:translate-x-0.5" />
            </button>
          </form>

          {/* Панель параметров */}
          <div className="py-6 flex flex-wrap items-center gap-x-8 gap-y-5">
            {/* Тип */}
            <label className="flex items-center gap-2 cursor-pointer">
              <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                Тип
              </span>
              <select
                value={typeId}
                onChange={(e) => {
                  setTypeId(e.target.value);
                  updateFilters({
                    type: e.target.value,
                    year_from: yearFrom,
                    year_to: yearTo,
                    genre_ids: selectedGenres,
                    sort_by: sortBy,
                    sort_order: sortOrder,
                  });
                }}
                className="bg-transparent border-0 border-b border-[var(--line)] rounded-none pl-0 pr-6 py-1 font-serif text-base text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-yellow)] cursor-pointer appearance-none"
              >
                <option value="">Все типы</option>
                {types.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name_ru}
                  </option>
                ))}
              </select>
            </label>

            {/* Годы */}
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                Год
              </span>
              <input
                type="number"
                placeholder="От"
                min="1900"
                max={new Date().getFullYear() + 5}
                value={yearFrom}
                onChange={(e) => setYearFrom(e.target.value)}
                onBlur={() =>
                  updateFilters({
                    year_from: yearFrom,
                    year_to: yearTo,
                    genre_ids: selectedGenres,
                    sort_by: sortBy,
                    sort_order: sortOrder,
                  })
                }
                className="w-16 bg-transparent border-0 border-b border-[var(--line)] rounded-none py-1 font-mono text-sm text-center text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-yellow)] placeholder:text-[var(--text-muted)]"
              />
              <span className="text-[var(--text-muted)] font-mono text-xs">—</span>
              <input
                type="number"
                placeholder="До"
                min="1900"
                max={new Date().getFullYear() + 5}
                value={yearTo}
                onChange={(e) => setYearTo(e.target.value)}
                onBlur={() =>
                  updateFilters({
                    year_from: yearFrom,
                    year_to: yearTo,
                    genre_ids: selectedGenres,
                    sort_by: sortBy,
                    sort_order: sortOrder,
                  })
                }
                className="w-16 bg-transparent border-0 border-b border-[var(--line)] rounded-none py-1 font-mono text-sm text-center text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-yellow)] placeholder:text-[var(--text-muted)]"
              />
            </div>

            {/* Жанры */}
            <div className="relative">
              <button
                type="button"
                onClick={() => {
                  console.log('Открываю dropdown жанров, текущее состояние:', isGenreDropdownOpen);
                  setIsGenreDropdownOpen(!isGenreDropdownOpen);
                }}
                className="group flex items-center gap-2 border-b border-[var(--line)] pb-1 hover:border-[var(--accent-yellow)] transition-colors"
              >
                <FunnelIcon className="w-4 h-4 text-[var(--text-muted)] group-hover:text-[var(--text-primary)] transition-colors" />
                <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                  Жанры
                </span>
                <span className="font-serif text-base text-[var(--text-primary)] truncate max-w-[140px]">
                  {selectedGenres.length > 0 ? `${selectedGenres.length} выбрано` : 'Все'}
                </span>
              </button>

              {isGenreDropdownOpen && (
                <>
                  <div
                    className="fixed inset-0 z-10"
                    onClick={() => setIsGenreDropdownOpen(false)}
                  />
                  <div className="absolute top-full left-0 mt-3 w-64 bg-[var(--bg-primary)] border border-[var(--line)] z-20 p-2 max-h-72 overflow-y-auto">
                    {genres.map((g) => {
                      const isSelected = selectedGenres.includes(String(g.id));
                      return (
                        <label
                          key={g.id}
                          className="group flex items-center gap-3 p-2 cursor-pointer hover:bg-[var(--bg-secondary)] transition-colors"
                        >
                          <span
                            className={`w-3.5 h-3.5 border transition-colors grid place-items-center shrink-0 ${
                              isSelected
                                ? 'bg-[var(--accent-yellow)] border-[var(--accent-yellow)]'
                                : 'border-[var(--line)] group-hover:border-[var(--text-primary)]'
                            }`}
                          >
                            {isSelected && (
                              <span className="w-1.5 h-1.5 bg-black" />
                            )}
                          </span>
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={(e) => {
                              const newGenres = e.target.checked
                                ? [...selectedGenres, String(g.id)]
                                : selectedGenres.filter((id) => id !== String(g.id));
                              setSelectedGenres(newGenres);
                              updateFilters({
                                genre_ids: newGenres,
                                year_from: yearFrom,
                                year_to: yearTo,
                                sort_by: sortBy,
                                sort_order: sortOrder,
                              });
                            }}
                            className="sr-only"
                          />
                          <span className="text-sm text-[var(--text-primary)]">{g.name_ru}</span>
                        </label>
                      );
                    })}
                  </div>
                </>
              )}
            </div>

            {/* Сортировка */}
            <label className="flex items-center gap-2 cursor-pointer">
              <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                Сортировка
              </span>
              <select
                value={`${sortBy}-${sortOrder}`}
                onChange={(e) => {
                  const [newSortBy, newSortOrder] = e.target.value.split('-');
                  setSortBy(newSortBy);
                  setSortOrder(newSortOrder);
                  updateFilters({
                    sort_by: newSortBy,
                    sort_order: newSortOrder,
                    year_from: yearFrom,
                    year_to: yearTo,
                    genre_ids: selectedGenres,
                  });
                }}
                className="bg-transparent border-0 border-b border-[var(--line)] rounded-none pl-0 pr-6 py-1 font-serif text-base text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-yellow)] cursor-pointer appearance-none"
              >
                <option value="release_date-desc">Сначала новые</option>
                <option value="release_date-asc">Сначала старые</option>
                <option value="title_ru-asc">По названию (А-Я)</option>
                <option value="title_ru-desc">По названию (Я-А)</option>
              </select>
            </label>

            {/* Кнопки */}
            <div className="ml-auto flex items-center gap-6">
              {hasActiveFilters && (
                <button
                  type="button"
                  onClick={handleReset}
                  className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] hover:text-[var(--text-primary)] border-b border-transparent hover:border-[var(--text-primary)] pb-0.5 transition-colors"
                >
                  Сбросить
                </button>
              )}
              <button
                type="button"
                onClick={() =>
                  updateFilters({
                    search,
                    type: typeId,
                    year_from: yearFrom,
                    year_to: yearTo,
                    genre_ids: selectedGenres,
                    sort_by: sortBy,
                    sort_order: sortOrder,
                  })
                }
                className="group inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-primary)] border-b border-[var(--text-primary)] pb-0.5 hover:border-[var(--accent-yellow)] transition-colors"
              >
                Применить
                <ArrowRightIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:translate-x-0.5" />
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* ============ РЕЗУЛЬТАТЫ ============ */}
      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
        {loading ? (
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 lg:gap-x-5 lg:gap-y-0 items-start">
            {Array.from({ length: limit }).map((_, i) => (
              <div key={i} className={STAGGER[i % 6]}>
                <div className="aspect-[2/3] rounded-[2px] bg-[var(--bg-tertiary)] animate-pulse" />
                <div className="mt-4 h-3 w-3/4 rounded bg-[var(--bg-tertiary)] animate-pulse" />
                <div className="mt-2 h-2 w-1/3 rounded bg-[var(--bg-tertiary)] animate-pulse" />
              </div>
            ))}
          </div>
        ) : mediaList.length === 0 ? (
          <motion.div
            {...fadeUp}
            transition={{ duration: 0.7, ease: EASE_OUT }}
            className="py-24 lg:py-32 text-center border-y border-[var(--line)]"
          >
            <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
              Пусто
            </p>
            <h3 className="font-serif text-4xl sm:text-5xl tracking-[-0.02em] mb-4">
              Ничего не найдено
            </h3>
            <p className="text-[var(--text-secondary)] max-w-md mx-auto">
              Попробуйте изменить параметры поиска или фильтры
            </p>
            {hasActiveFilters && (
              <button
                type="button"
                onClick={handleReset}
                className="mt-8 inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-primary)] border-b border-[var(--text-primary)] pb-0.5 hover:border-[var(--accent-yellow)] transition-colors"
              >
                Сбросить фильтры
              </button>
            )}
          </motion.div>
        ) : (
          <>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 lg:gap-x-5 lg:gap-y-0 items-start">
              {mediaList.map((media, index) => (
                <motion.div
                  key={media.id}
                  {...fadeUp}
                  transition={{
                    duration: 0.7,
                    delay: Math.min(index * 0.04, 0.4),
                    ease: EASE_OUT,
                  }}
                  className={STAGGER[index % 6]}
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
                      <span className="pointer-events-none absolute inset-0 bg-gradient-to-t from-black/85 via-black/0 to-black/0 opacity-0 group-hover:opacity-100 transition-opacity duration-700" />

                      {/* Тонкая золотая рамка */}
                      <span className="pointer-events-none absolute inset-2 border border-transparent group-hover:border-[var(--accent-yellow)]/70 transition-colors duration-700" />

                      {/* Порядковый номер */}
                      <span className="absolute top-3 left-3 font-mono text-[10px] tracking-[0.15em] text-white/50 mix-blend-difference opacity-0 group-hover:opacity-100 transition-opacity duration-500">
                        {String(index + 1).padStart(2, '0')}
                      </span>

                      {/* Стрелка снизу */}
                      <span className="absolute bottom-3 right-3 w-8 h-8 grid place-items-center bg-black/60 backdrop-blur-sm text-white opacity-0 translate-y-2 group-hover:opacity-100 group-hover:translate-y-0 transition-all duration-500">
                        <ArrowRightIcon className="w-3.5 h-3.5" />
                      </span>
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

            {/* ============ ПАГИНАЦИЯ ============ */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between gap-4 mt-20 lg:mt-28 pt-8 border-t border-[var(--line)]">
                <Button
                  variant="secondary"
                  onClick={() => updatePage(Math.max(1, currentPage - 1))}
                  disabled={currentPage === 1}
                  className="inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  <ChevronLeftIcon className="w-4 h-4" />
                  <span className="hidden sm:inline">Назад</span>
                </Button>

                <div className="font-serif text-2xl sm:text-3xl tracking-[-0.02em]">
                  <span className="italic text-[var(--accent-yellow)]">
                    {String(currentPage).padStart(2, '0')}
                  </span>
                  <span className="text-[var(--text-muted)] mx-2 text-xl">/</span>
                  <span className="text-[var(--text-muted)]">
                    {String(totalPages).padStart(2, '0')}
                  </span>
                </div>

                <Button
                  variant="secondary"
                  onClick={() => updatePage(Math.min(totalPages, currentPage + 1))}
                  disabled={currentPage === totalPages}
                  className="inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  <span className="hidden sm:inline">Вперёд</span>
                  <ChevronRightIcon className="w-4 h-4" />
                </Button>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}