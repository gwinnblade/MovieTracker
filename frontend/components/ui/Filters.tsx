// frontend/components/ui/Filters.tsx
'use client';

import { useEffect, useState } from 'react';
import {
  MagnifyingGlassIcon,
  XMarkIcon,
  ArrowRightIcon,
  FunnelIcon,
} from '@heroicons/react/24/outline';

export interface FilterType {
  id: number;
  name_ru: string;
}

interface FiltersProps {
  search: string;
  type_id: number | null;
  sort_by: string;
  sort_direction: 'asc' | 'desc';
  types?: FilterType[];
  loading?: boolean;
  onSearchChange: (value: string) => void;
  onTypeChange: (value: number | null) => void;
  onSortChange: (sortBy: string, direction: 'asc' | 'desc') => void;
  onReset: () => void;
}

const SORT_OPTIONS = [
  { value: 'created_at:desc', label: 'Сначала новые' },
  { value: 'created_at:asc', label: 'Сначала старые' },
  { value: 'title_ru:asc', label: 'По названию (А-Я)' },
  { value: 'title_ru:desc', label: 'По названию (Я-А)' },
  { value: 'release_date:desc', label: 'По дате выхода (новые)' },
  { value: 'release_date:asc', label: 'По дате выхода (старые)' },
];

const SELECT_CLASS =
  'bg-transparent border-0 border-b border-[var(--line)] rounded-none px-0 pr-8 py-1.5 font-serif text-base text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-yellow)] transition-colors disabled:opacity-50 cursor-pointer appearance-none';

export default function Filters({
  search,
  type_id,
  sort_by,
  sort_direction,
  types = [],
  loading = false,
  onSearchChange,
  onTypeChange,
  onSortChange,
  onReset,
}: FiltersProps) {
  const [localSearch, setLocalSearch] = useState(search);

  useEffect(() => {
    setLocalSearch(search);
  }, [search]);

  const sortValue = `${sort_by}:${sort_direction}`;
  const hasActiveFilters =
    !!search || type_id !== null || sort_by !== 'created_at' || sort_direction !== 'desc';

  const submitSearch = (e: React.FormEvent) => {
    e.preventDefault();
    onSearchChange(localSearch.trim());
  };

  const clearSearch = () => {
    setLocalSearch('');
    onSearchChange('');
  };

  return (
    <section className="border-y border-[var(--line)] bg-[var(--bg-secondary)]">
      <div className="max-w-[1400px] mx-auto px-6 lg:px-10">
        {/* ===== Строка поиска — крупная, редакционная ===== */}
        <form
          role="search"
          onSubmit={submitSearch}
          className="flex items-center gap-4 py-6 lg:py-8 border-b border-[var(--line)]"
        >
          <MagnifyingGlassIcon
            className="w-5 h-5 shrink-0 text-[var(--text-muted)]"
            aria-hidden="true"
          />

          <input
            id="filter-search"
            type="search"
            value={localSearch}
            onChange={(e) => setLocalSearch(e.target.value)}
            placeholder="Поиск по названию…"
            disabled={loading}
            aria-label="Поиск по названию"
            className="flex-1 min-w-0 bg-transparent border-0 outline-none font-serif text-xl sm:text-2xl lg:text-3xl tracking-[-0.01em] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] placeholder:italic placeholder:opacity-60 [&::-webkit-search-cancel-button]:hidden disabled:opacity-50"
          />

          {localSearch && (
            <button
              type="button"
              onClick={clearSearch}
              disabled={loading}
              aria-label="Очистить поиск"
              className="text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors disabled:opacity-50 shrink-0"
            >
              <XMarkIcon className="w-4 h-4" aria-hidden="true" />
            </button>
          )}

          <button
            type="submit"
            disabled={loading}
            className="group inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors shrink-0 disabled:opacity-40"
          >
            <span className="hidden sm:inline">
              {loading ? 'Ищем…' : 'Найти'}
            </span>
            <ArrowRightIcon className="w-4 h-4 transition-transform duration-500 group-hover:translate-x-0.5" />
          </button>
        </form>

        {/* ===== Строка параметров ===== */}
        <div className="py-5 flex flex-wrap items-center gap-x-8 gap-y-4">
          <div className="flex items-center gap-2 shrink-0">
            <FunnelIcon className="w-3.5 h-3.5 text-[var(--text-muted)]" aria-hidden="true" />
            <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
              Фильтры
            </span>
          </div>

          <span className="hidden sm:block h-3 w-px bg-[var(--line)]" aria-hidden="true" />

          {/* Тип */}
          <label className="flex items-baseline gap-3 cursor-pointer">
            <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] shrink-0">
              Тип
            </span>
            <select
              id="filter-type"
              value={type_id ?? ''}
              onChange={(e) => onTypeChange(e.target.value ? Number(e.target.value) : null)}
              disabled={loading}
              aria-label="Тип медиа"
              className={SELECT_CLASS}
            >
              <option value="">Все типы</option>
              {types.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name_ru}
                </option>
              ))}
            </select>
          </label>

          {/* Сортировка */}
          <label className="flex items-baseline gap-3 cursor-pointer">
            <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] shrink-0">
              Сортировка
            </span>
            <select
              id="filter-sort"
              value={sortValue}
              onChange={(e) => {
                const [sortBy, direction] = e.target.value.split(':');
                onSortChange(sortBy, direction as 'asc' | 'desc');
              }}
              disabled={loading}
              aria-label="Сортировка"
              className={SELECT_CLASS}
            >
              {SORT_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>

          {/* Сброс */}
          <div className="ml-auto">
            {hasActiveFilters && (
              <button
                type="button"
                onClick={onReset}
                disabled={loading}
                className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] hover:text-[var(--text-primary)] border-b border-transparent hover:border-[var(--text-primary)] pb-0.5 transition-colors disabled:opacity-40"
              >
                Сбросить
              </button>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}