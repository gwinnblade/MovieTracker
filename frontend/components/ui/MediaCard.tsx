// frontend/components/ui/MediaCard.tsx
'use client';
import Image from 'next/image';
import { useState } from 'react';
import { FilmIcon, ArrowUpRightIcon } from '@heroicons/react/24/outline';
import { Media } from '@/lib/api/media';
import { resolveMediaUrl } from '@/lib/utils/media-url';

interface MediaCardProps {
  media: Media;
}

const TYPE_ACCENT: Record<string, string> = {
  movie: 'var(--accent-yellow)',
  series: 'var(--accent-blue, #6a8fc4)',
  anime: 'var(--accent-green)',
  cartoon: 'var(--accent-purple)',
};

function getYear(release_date?: string | null): number | null {
  if (!release_date) return null;
  const d = new Date(release_date);
  const y = d.getFullYear();
  return Number.isNaN(y) ? null : y;
}

export default function MediaCard({ media }: MediaCardProps) {
  const [imageFailed, setImageFailed] = useState(false);

  const posterUrl = resolveMediaUrl(media.poster_url);
  const year = getYear(media.release_date);
  const title = media.title_ru?.trim() || 'Без названия';
  const accent = TYPE_ACCENT[media.type?.code ?? ''] ?? 'var(--accent-yellow)';
  const showImage = Boolean(posterUrl) && !imageFailed;

  return (
    <a
      href={`/media/${media.id}`}
      className="group block focus-visible:outline-none"
      aria-label={`Открыть «${title}»${year ? `, ${year}` : ''}`}
    >
      {/* ===== Постер ===== */}
      <div className="relative aspect-[2/3] overflow-hidden rounded-[2px] bg-[var(--bg-tertiary)]">
        {showImage ? (
          <Image
            src={resolveMediaUrl(posterUrl)!}
            alt=""
            fill
            sizes="(max-width: 768px) 160px, 240px"
            onError={() => setImageFailed(true)}
            className="object-cover transition-transform duration-[1400ms] ease-[cubic-bezier(0.76,0,0.24,1)] group-hover:scale-[1.08]"
          />
        ) : (
          <div className="w-full h-full grid place-items-center text-[var(--text-muted)]">
            <FilmIcon className="w-10 h-10 opacity-30" aria-hidden="true" />
          </div>
        )}

        {/* Градиент — мягкое проявление снизу */}
        <span
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 bg-gradient-to-t from-black/85 via-black/0 to-black/0 opacity-0 group-hover:opacity-100 transition-opacity duration-700"
        />

        {/* Тонкая золотая рамка-инсет */}
        <span
          aria-hidden="true"
          className="pointer-events-none absolute inset-2 border border-transparent group-hover:border-[var(--accent-yellow)]/70 transition-colors duration-700"
        />

        {/* Тип — тонкая метка сверху, без заливки */}
        {media.type && (
          <span className="absolute top-3 left-3 inline-flex items-center gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity duration-500">
            <span
              className="w-1.5 h-1.5 rounded-full shrink-0"
              style={{ background: accent }}
            />
            <span className="font-mono text-[9px] uppercase tracking-[0.2em] text-white/90">
              {media.type.name_ru}
            </span>
          </span>
        )}

        {/* Стрелка снизу */}
        <span className="absolute bottom-3 right-3 w-8 h-8 grid place-items-center bg-black/60 backdrop-blur-sm text-white opacity-0 translate-y-2 group-hover:opacity-100 group-hover:translate-y-0 transition-all duration-500">
          <ArrowUpRightIcon className="w-3.5 h-3.5" />
        </span>
      </div>

      {/* ===== Подпись — редакционная ===== */}
      <div className="mt-4 min-w-0">
        <h3 className="font-serif text-base leading-snug line-clamp-2 text-[var(--text-primary)] group-hover:italic transition-[font-style] duration-300">
          {title}
        </h3>
        <div className="mt-1.5 flex items-baseline gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
          {year != null && <span className="tabular-nums">{year}</span>}
          {media.type && year != null && (
            <span className="text-[var(--text-muted)]/50">·</span>
          )}
          {media.type && (
            <span className="truncate">{media.type.name_ru}</span>
          )}
        </div>
      </div>
    </a>
  );
}