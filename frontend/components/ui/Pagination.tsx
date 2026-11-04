// frontend/components/ui/Pagination.tsx
'use client';

import {
  ChevronLeftIcon,
  ChevronRightIcon,
} from '@heroicons/react/24/outline';

interface PaginationProps {
  currentPage: number;
  lastPage: number;
  onPageChange: (page: number) => void;
  siblings?: number;
}

type PageItem = number | 'ellipsis-left' | 'ellipsis-right';

function buildPages(current: number, total: number, siblings: number): PageItem[] {
  if (total <= 1) return [];

  const maxWithoutEllipsis = siblings * 2 + 5;
  if (total <= maxWithoutEllipsis) {
    return Array.from({ length: total }, (_, i) => i + 1);
  }

  const leftSibling = Math.max(current - siblings, 2);
  const rightSibling = Math.min(current + siblings, total - 1);

  const items: PageItem[] = [1];
  if (leftSibling > 2) items.push('ellipsis-left');
  for (let i = leftSibling; i <= rightSibling; i++) items.push(i);
  if (rightSibling < total - 1) items.push('ellipsis-right');
  items.push(total);

  return items;
}

export default function Pagination({
  currentPage,
  lastPage,
  onPageChange,
  siblings = 1,
}: PaginationProps) {
  if (lastPage <= 1) return null;

  const pages = buildPages(currentPage, lastPage, siblings);
  const canPrev = currentPage > 1;
  const canNext = currentPage < lastPage;

  return (
    <nav
      aria-label="Пагинация"
      className="mt-20 lg:mt-28 pt-10 border-t border-[var(--line)] flex items-center justify-between gap-6"
    >
      {/* Назад */}
      <button
        type="button"
        onClick={() => onPageChange(currentPage - 1)}
        disabled={!canPrev}
        aria-label="Предыдущая страница"
        className="group inline-flex items-center gap-3 disabled:opacity-30 disabled:cursor-not-allowed shrink-0"
      >
        <span className="w-10 h-10 rounded-full border border-[var(--line)] grid place-items-center transition-colors duration-500 group-hover:border-[var(--text-primary)] group-disabled:group-hover:border-[var(--line)]">
          <ChevronLeftIcon className="w-4 h-4 transition-transform duration-500 group-hover:-translate-x-0.5" aria-hidden="true" />
        </span>
        <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors hidden sm:inline">
          Назад
        </span>
      </button>

      {/* Номера страниц — редакционный «индекс» */}
      <div className="hidden sm:flex items-baseline gap-1">
        {pages.map((item) => {
          if (typeof item === 'number') {
            const active = item === currentPage;
            return (
              <button
                key={item}
                type="button"
                onClick={() => onPageChange(item)}
                aria-label={`Страница ${item}`}
                aria-current={active ? 'page' : undefined}
                className={`group relative px-2.5 py-1 font-serif transition-colors duration-300 ${
                  active
                    ? 'text-[var(--text-primary)]'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                }`}
              >
                <span
                  className={`tabular-nums ${
                    active ? 'text-2xl italic tracking-[-0.02em]' : 'text-lg'
                  }`}
                >
                  {String(item).padStart(2, '0')}
                </span>
                {active && (
                  <span
                    aria-hidden
                    className="absolute -bottom-0.5 left-1/2 -translate-x-1/2 w-1 h-1 rounded-full bg-[var(--accent-yellow)]"
                  />
                )}
              </button>
            );
          }
          return (
            <span
              key={item}
              aria-hidden="true"
              className="inline-flex items-center justify-center px-1.5 text-[var(--text-muted)]/50 select-none font-mono text-xs"
            >
              …
            </span>
          );
        })}
      </div>

      {/* Компактный индикатор на мобильном */}
      <div className="sm:hidden flex items-baseline gap-2 font-serif">
        <span className="text-2xl italic tabular-nums text-[var(--accent-yellow)]">
          {String(currentPage).padStart(2, '0')}
        </span>
        <span className="text-[var(--text-muted)] text-lg">/</span>
        <span className="text-[var(--text-muted)] text-lg tabular-nums">
          {String(lastPage).padStart(2, '0')}
        </span>
      </div>

      {/* Вперёд */}
      <button
        type="button"
        onClick={() => onPageChange(currentPage + 1)}
        disabled={!canNext}
        aria-label="Следующая страница"
        className="group inline-flex items-center gap-3 disabled:opacity-30 disabled:cursor-not-allowed shrink-0"
      >
        <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors hidden sm:inline">
          Вперёд
        </span>
        <span className="w-10 h-10 rounded-full border border-[var(--line)] grid place-items-center transition-colors duration-500 group-hover:border-[var(--text-primary)] group-disabled:group-hover:border-[var(--line)]">
          <ChevronRightIcon className="w-4 h-4 transition-transform duration-500 group-hover:translate-x-0.5" aria-hidden="true" />
        </span>
      </button>
    </nav>
  );
}