"use client";

import Image from "next/image";
import Link from "next/link";
import {
  ArrowLeftIcon,
  ArrowRightIcon,
  BookmarkSquareIcon,
  UserIcon,
  XMarkIcon,
} from "@heroicons/react/24/outline";
import { StarIcon } from "@heroicons/react/24/solid";
import { useQuery } from "@tanstack/react-query";
import {
  useEffect,
  useRef,
  useState,
  type ComponentPropsWithRef,
  type ReactNode,
} from "react";
import { api, errorMessage, imageUrl, mediaHref } from "@/lib/api";
import type { Media } from "@/lib/types";

const controlClasses = [
  "block min-h-12 w-full min-w-0 appearance-none rounded-xl border border-white/10",
  "bg-[#0B0E14] px-4 py-3 text-sm text-white placeholder:text-zinc-500 outline-none",
  "transition-[background-color,border-color,box-shadow] duration-200 ease-out",
  "enabled:hover:border-white/20 focus:border-gold focus:ring-2 focus:ring-gold/15",
  "disabled:cursor-not-allowed disabled:opacity-40 motion-reduce:transition-none",
].join(" ");

const toggleClasses = [
  "ui-control peer m-0 size-5 shrink-0 cursor-pointer appearance-none",
  "border border-white/15 bg-[#0B0E14] outline-none",
  "transition-[background-color,border-color,box-shadow] duration-200 ease-out",
  "enabled:hover:border-gold/60 checked:border-gold checked:bg-gold/10",
  "focus-visible:border-gold focus-visible:ring-2 focus-visible:ring-gold/25",
  "focus-visible:ring-offset-2 focus-visible:ring-offset-graphite",
  "disabled:cursor-not-allowed motion-reduce:transition-none",
].join(" ");

const buttonClasses = [
  "inline-flex min-h-12 cursor-pointer items-center justify-center gap-2 rounded-xl border",
  "px-5 py-3 text-sm font-semibold leading-5 outline-none",
  "transition-[background-color,border-color,color,box-shadow,transform] duration-200 ease-out",
  "focus-visible:ring-2 focus-visible:ring-gold/40",
  "focus-visible:ring-offset-2 focus-visible:ring-offset-graphite",
  "enabled:active:scale-95 disabled:cursor-not-allowed disabled:opacity-40",
  "motion-reduce:transform-none motion-reduce:transition-none",
].join(" ");

const buttonVariants = {
  primary:
    "border-gold bg-gold text-[#17120a] enabled:hover:border-gold-hover enabled:hover:bg-gold-hover enabled:hover:shadow-[0_0_15px_rgba(229,169,61,0.4)]",
  secondary:
    "border-white/20 bg-transparent text-white enabled:hover:border-white/35 enabled:hover:bg-white/5",
  ghost:
    "border-transparent bg-transparent text-muted enabled:hover:text-gold",
  danger:
    "border-red-500/30 bg-red-500/10 text-red-400 enabled:hover:border-red-500/50 enabled:hover:bg-red-500/20 enabled:hover:text-red-300 enabled:hover:shadow-[0_0_15px_rgba(239,68,68,0.2)]",
};

export function Input({
  className = "",
  ...props
}: ComponentPropsWithRef<"input">) {
  return (
    <input
      {...props}
      className={`ui-control ${controlClasses} file:mr-4 file:cursor-pointer file:rounded-lg file:border-0 file:bg-white/5 file:px-3 file:py-1.5 file:text-xs file:font-medium file:text-muted file:transition-colors hover:file:bg-white/10 ${className}`}
    />
  );
}

export function Select({
  className = "",
  children,
  multiple,
  size,
  ...props
}: ComponentPropsWithRef<"select">) {
  const showArrow = !multiple && (size === undefined || size <= 1);

  return (
    <div className="relative w-full min-w-0">
      <select
        {...props}
        multiple={multiple}
        size={size}
        className={`ui-control peer ${controlClasses} cursor-pointer ${showArrow ? "pr-11" : ""} ${className}`}
      >
        {children}
      </select>
      {showArrow && (
        <svg
          className="pointer-events-none absolute top-1/2 right-4 size-4 -translate-y-1/2 text-muted transition-colors duration-200 peer-focus:text-gold peer-disabled:opacity-40 motion-reduce:transition-none"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.75"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
          focusable="false"
        >
          <path d="m6 9 6 6 6-6" />
        </svg>
      )}
    </div>
  );
}

export function Button({
  variant = "primary",
  className = "",
  ...props
}: ComponentPropsWithRef<"button"> & {
  variant?: keyof typeof buttonVariants;
}) {
  return (
    <button
      {...props}
      className={`${buttonClasses} ${buttonVariants[variant]} ${className}`}
    />
  );
}

export function Checkbox({
  className = "",
  ...props
}: Omit<ComponentPropsWithRef<"input">, "type">) {
  return (
    <span className="relative inline-flex shrink-0 align-middle has-[:disabled]:opacity-40">
      <input
        {...props}
        type="checkbox"
        className={`${toggleClasses} rounded-md indeterminate:border-gold indeterminate:bg-gold/10 ${className}`}
      />
      <svg
        className="pointer-events-none absolute inset-0 m-auto size-3.5 text-gold opacity-0 transition-opacity duration-200 peer-checked:opacity-100 peer-indeterminate:hidden motion-reduce:transition-none"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
        focusable="false"
      >
        <path d="m5 12 4 4L19 6" />
      </svg>
      <span
        className="pointer-events-none absolute inset-0 m-auto h-0.5 w-2.5 rounded-full bg-gold opacity-0 transition-opacity duration-200 peer-indeterminate:opacity-100 motion-reduce:transition-none"
        aria-hidden="true"
      />
    </span>
  );
}

export function Radio({
  className = "",
  ...props
}: Omit<ComponentPropsWithRef<"input">, "type">) {
  return (
    <span className="relative inline-flex shrink-0 align-middle has-[:disabled]:opacity-40">
      <input
        {...props}
        type="radio"
        className={`${toggleClasses} rounded-full ${className}`}
      />
      <span
        className="pointer-events-none absolute inset-0 m-auto size-2 rounded-full bg-gold opacity-0 transition-opacity duration-200 peer-checked:opacity-100 motion-reduce:transition-none"
        aria-hidden="true"
      />
    </span>
  );
}

export function Textarea({
  className = "",
  ...props
}: ComponentPropsWithRef<"textarea">) {
  return (
    <textarea
      {...props}
      className={`ui-control ${controlClasses} min-h-32 resize-y leading-relaxed ${className}`}
    />
  );
}

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
          <UserIcon className="avatar-placeholder-icon" aria-hidden="true" />
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
            <StarIcon className="ui-icon" aria-hidden="true" />
            {Number(rating ?? cardMedia.vote_average ?? cardMedia.avg_rating).toFixed(
              1,
            )}
          </span>
        ) : null}
        <span className="poster-preview" aria-hidden="true">
          Открыть карточку
          <ArrowRightIcon className="ui-icon" />
        </span>
      </div>
      <h3>{cardMedia.title_ru}</h3>
      <div className="media-meta">
        <p>
          {cardMedia.release_date?.slice(0, 4) || "Год не указан"}
          {caption ? " · " + caption : ""}
        </p>
        <span className="media-type">
          {cardMedia.type?.name_ru ||
            (cardMedia.tmdb_type === "tv" ? "Сериал" : "Фильм")}
        </span>
      </div>
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
      <span className="empty-icon">
        <BookmarkSquareIcon aria-hidden="true" />
      </span>
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
        <ArrowLeftIcon className="ui-icon" aria-hidden="true" /> Назад
      </button>
      <span>
        {page} / {last} <small>· Всего {total}</small>
      </span>
      <button
        className="button secondary"
        disabled={page >= last}
        onClick={() => onChange(page + 1)}
      >
        Дальше <ArrowRightIcon className="ui-icon" aria-hidden="true" />
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
          <XMarkIcon className="ui-icon" aria-hidden="true" />
        </button>
      </div>
      {children}
    </dialog>
  );
}