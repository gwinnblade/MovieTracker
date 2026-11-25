"use client";

import Image from "next/image";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { api, errorMessage, imageUrl, mediaHref } from "@/lib/api";
import type { Media } from "@/lib/types";

export function Artwork({
  src,
  alt,
  className = "",
  priority = false,
}: {
  src?: string | null;
  alt: string;
  className?: string;
  priority?: boolean;
}) {
  const [failed, setFailed] = useState<string | undefined>();
  const url = imageUrl(src);
  return (
    <div className={"artwork " + className}>
      {url && failed !== url ? (
        <Image
          src={url}
          alt={alt}
          fill
          sizes="(max-width: 640px) 45vw, 240px"
          unoptimized
          priority={priority}
          onError={() => setFailed(url)}
        />
      ) : (
        <div className="artwork-placeholder">
          <svg viewBox="0 0 32 32" aria-hidden="true">
            <rect x="4" y="3" width="24" height="26" rx="3" />
            <path d="M4 10h24M4 22h24M11 3v7m10-7v7M11 22v7m10-7v7" />
          </svg>
          <span>Нет изображения</span>
        </div>
      )}
    </div>
  );
}
export function MediaCard({
  media,
  rating,
  caption,
}: {
  media: Media;
  rating?: number | null;
  caption?: string;
}) {
  const details = useQuery({
    queryKey: ["detail", true, media.tmdb_type, media.tmdb_id],
    queryFn: () => api.tmdbDetails(media.tmdb_type!, media.tmdb_id!),
    enabled: !!media.tmdb_id && !!media.tmdb_type && /TMDB #\d+$/.test(media.title_ru),
    staleTime: 86400000,
  });
  const cardMedia = details.data ? { ...media, ...details.data } : media;
  return (
    <Link href={mediaHref(cardMedia)} className="media-card">
      <div className="poster-wrap">
        <Artwork
          src={cardMedia.poster_url || cardMedia.poster_key}
          alt={cardMedia.title_ru}
        />
        {(rating ?? cardMedia.vote_average ?? cardMedia.avg_rating) ? (
          <span className="rating-chip">
            ★{" "}
            {Number(rating ?? cardMedia.vote_average ?? cardMedia.avg_rating).toFixed(
              1,
            )}
          </span>
        ) : null}
        <span className="type-chip">
          {cardMedia.type?.name_ru ||
            (cardMedia.tmdb_type === "tv" ? "Сериал" : "Фильм")}
        </span>
      </div>
      <h3>{cardMedia.title_ru}</h3>
      <p>
        {cardMedia.release_date?.slice(0, 4) || "Год не указан"}
        {caption ? " · " + caption : ""}
      </p>
    </Link>
  );
}
export function MediaGrid({ items }: { items: Media[] }) {
  return (
    <div className="media-grid">
      {items.map((media) => (
        <MediaCard
          key={media.id || `${media.tmdb_type}-${media.tmdb_id}`}
          media={media}
        />
      ))}
    </div>
  );
}
export function Loading({ text = "Загрузка…" }: { text?: string }) {
  return (
    <div className="loading" role="status">
      <span className="spinner" />
      {text}
    </div>
  );
}
export function ErrorState({
  error,
  retry,
}: {
  error: unknown;
  retry?: () => void;
}) {
  return (
    <div className="notice error" role="alert">
      <p>{errorMessage(error)}</p>
      {retry && (
        <button className="button secondary" onClick={retry}>
          Попробовать снова
        </button>
      )}
    </div>
  );
}
export function Empty({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty-state panel">
      <span className="empty-icon">◇</span>
      <h2>{title}</h2>
      {children}
    </div>
  );
}
export function PageHeading({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  children?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        {eyebrow && <span className="eyebrow">{eyebrow}</span>}
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {children}
    </div>
  );
}
export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}
export function Pagination({
  page,
  last,
  total,
  onChange,
}: {
  page: number;
  last: number;
  total: number;
  onChange: (page: number) => void;
}) {
  return last > 1 ? (
    <div className="pagination">
      <button
        className="button secondary"
        disabled={page <= 1}
        onClick={() => onChange(page - 1)}
      >
        ← Назад
      </button>
      <span>
        {page} / {last} <small>· Всего {total}</small>
      </span>
      <button
        className="button secondary"
        disabled={page >= last}
        onClick={() => onChange(page + 1)}
      >
        Дальше →
      </button>
    </div>
  ) : null;
}
export function Modal({
  title,
  children,
  onClose,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    dialog?.showModal();
    return () => {
      dialog?.close();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className="modal panel"
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        if (event.target === ref.current) onClose();
      }}
    >
      <div className="modal-heading">
        <h2>{title}</h2>
        <button className="icon-button" onClick={onClose} aria-label="Закрыть">
          ×
        </button>
      </div>
      {children}
    </dialog>
  );
}
