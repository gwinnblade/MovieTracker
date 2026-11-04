// frontend/components/ui/EpisodeList.tsx
'use client';

import { useMemo, useState } from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { Episode } from '@/lib/api/media';
import { ChevronDownIcon, ArrowRightIcon } from '@heroicons/react/24/outline';

interface EpisodeListProps {
  episodes: Episode[];
  /** Сколько сезонов открыть по умолчанию. */
  initiallyOpen?: number;
}

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const EASE_EDITORIAL = [0.76, 0, 0.24, 1] as const;

function plural(n: number, one: string, few: string, many: string): string {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return one;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return few;
  return many;
}

function formatDuration(minutes?: number | null): string | null {
  if (!minutes || minutes <= 0) return null;
  if (minutes < 60) return `${minutes} мин`;
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return m > 0 ? `${h} ч ${m} мин` : `${h} ч`;
}

function formatEpisodeNumber(season: number, number: number): string {
  if (season === 0) return `E${String(number).padStart(2, '0')}`;
  return `S${String(season).padStart(2, '0')}E${String(number).padStart(2, '0')}`;
}

export default function EpisodeList({
  episodes,
  initiallyOpen = 1,
}: EpisodeListProps) {
  const prefersReduced = useReducedMotion();

  const seasons = useMemo(() => {
    const map = new Map<number, Episode[]>();
    for (const ep of episodes ?? []) {
      const s = ep.season ?? 0;
      if (!map.has(s)) map.set(s, []);
      map.get(s)!.push(ep);
    }
    // Сортируем эпизоды внутри сезона, не мутируя исходный массив
    for (const eps of map.values()) {
      eps.sort((a, b) => (a.number ?? 0) - (b.number ?? 0));
    }
    return Array.from(map.entries()).sort(([a], [b]) => a - b);
  }, [episodes]);

  const [openSeasons, setOpenSeasons] = useState<Set<number>>(() => {
    const initial = new Set<number>();
    seasons.slice(0, initiallyOpen).forEach(([s]) => initial.add(s));
    return initial;
  });

  if (seasons.length === 0) return null;

  const toggleSeason = (season: number) => {
    setOpenSeasons((prev) => {
      const next = new Set(prev);
      if (next.has(season)) next.delete(season);
      else next.add(season);
      return next;
    });
  };

  return (
    <section aria-labelledby="episodes-heading">
      <div className="space-y-16">
        {seasons.map(([season, eps], seasonIdx) => {
          const open = openSeasons.has(season);
          const heading = season === 0 ? 'Спецвыпуски' : `Сезон ${season}`;
          const countLabel = `${eps.length} ${plural(
            eps.length,
            'эпизод',
            'эпизода',
            'эпизодов'
          )}`;

          return (
            <div key={season}>
              {/* Редакционный заголовок сезона — асимметричный, как журнальная врезка */}
              <button
                type="button"
                onClick={() => toggleSeason(season)}
                aria-expanded={open}
                aria-controls={`season-${season}-episodes`}
                className="group w-full text-left focus-visible:outline-none"
              >
                <div className="grid lg:grid-cols-12 gap-4 lg:gap-6 items-baseline pb-4 border-b border-[var(--line)]">
                  <div className="lg:col-span-2 flex items-baseline gap-3">
                    <span className="font-mono text-[10px] tracking-[0.25em] text-[var(--text-muted)] tabular-nums">
                      {String(seasonIdx + 1).padStart(2, '0')}
                    </span>
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-yellow)] self-center opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                  </div>

                  <div className="lg:col-span-7 min-w-0">
                    <h3 className="font-serif text-3xl sm:text-4xl lg:text-5xl leading-[0.92] tracking-[-0.03em] text-[var(--text-primary)] group-hover:italic transition-[font-style] duration-300 break-words">
                      {heading}
                    </h3>
                    <p className="mt-3 font-mono text-[10px] uppercase tracking-[0.22em] text-[var(--text-muted)] tabular-nums">
                      {countLabel}
                    </p>
                  </div>

                  <div className="lg:col-span-3 lg:text-right">
                    <span className="inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] group-hover:text-[var(--text-primary)] transition-colors">
                      <span className="hidden sm:inline">
                        {open ? 'Свернуть' : 'Развернуть'}
                      </span>
                      <ChevronDownIcon
                        className={`w-3.5 h-3.5 shrink-0 transition-transform duration-500 ${
                          open ? 'rotate-180' : ''
                        }`}
                        aria-hidden="true"
                      />
                    </span>
                  </div>
                </div>
              </button>

              <AnimatePresence initial={false}>
                {open && (
                  <motion.div
                    id={`season-${season}-episodes`}
                    initial={prefersReduced ? false : { opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={prefersReduced ? undefined : { opacity: 0, height: 0 }}
                    transition={{ duration: 0.5, ease: EASE_EDITORIAL }}
                    className="overflow-hidden"
                  >
                    <ol>
                      {eps.map((ep, i) => {
                        const duration = formatDuration(ep.duration);
                        const title = ep.title_ru || (ep as any).title_en;
                        const epNum = formatEpisodeNumber(
                          ep.season ?? 0,
                          ep.number ?? 0
                        );

                        return (
                          <motion.li
                            key={ep.id}
                            initial={prefersReduced ? false : { opacity: 0, y: 8 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{
                              duration: 0.4,
                              delay: Math.min(i * 0.03, 0.25),
                              ease: EASE_OUT,
                            }}
                            className="group border-b border-[var(--line)]"
                          >
                            <div className="grid lg:grid-cols-12 gap-4 lg:gap-6 py-5 items-start">
                              {/* Номер эпизода — крупная метка слева */}
                              <div className="lg:col-span-2 flex items-baseline gap-3">
                                <span
                                  className="font-mono text-[10px] font-medium tracking-[0.2em] text-[var(--text-muted)] tabular-nums shrink-0 group-hover:text-[var(--accent-yellow)] transition-colors"
                                  aria-label={`Эпизод ${epNum}`}
                                >
                                  {epNum}
                                </span>
                              </div>

                              {/* Заголовок + описание */}
                              <div className="lg:col-span-8 min-w-0">
                                <p className="font-serif text-lg sm:text-xl leading-tight text-[var(--text-primary)] group-hover:italic transition-[font-style] duration-300">
                                  {title || `Эпизод ${ep.number ?? ''}`}
                                </p>
                                {ep.description_ru && (
                                  <p className="mt-2 text-sm text-[var(--text-secondary)] leading-relaxed line-clamp-2 max-w-2xl">
                                    {ep.description_ru}
                                  </p>
                                )}
                              </div>

                              {/* Длительность */}
                              <div className="lg:col-span-2 lg:text-right">
                                {duration && (
                                  <span className="inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)] tabular-nums whitespace-nowrap">
                                    {duration}
                                    <ArrowRightIcon
                                      className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity duration-500"
                                      aria-hidden="true"
                                    />
                                  </span>
                                )}
                              </div>
                            </div>
                          </motion.li>
                        );
                      })}
                    </ol>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </div>
    </section>
  );
}