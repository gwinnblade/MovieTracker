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
  "block min-h-12 w-full min-w-0 appearance-none border-2 border-white/20",
  "bg-[var(--bg)] px-4 py-3 text-sm text-[var(--text)] placeholder:text-[var(--subtle)] outline-none",
  "transition-[border-color,background-color] duration-150 ease-out",
  "enabled:hover:border-white/40 focus:border-[var(--accent)]",
  "disabled:cursor-not-allowed disabled:opacity-40 motion-reduce:transition-none",
].join(" ");

const toggleClasses = [
  "ui-control peer m-0 size-5 shrink-0 cursor-pointer appearance-none",
  "border-2 border-white/20 bg-[var(--bg)] outline-none",
  "transition-[border-color,background-color] duration-150 ease-out",
  "enabled:hover:border-[var(--accent)] checked:border-[var(--accent)] checked:bg-[var(--accent)]",
  "disabled:cursor-not-allowed motion-reduce:transition-none",
].join(" ");

const buttonClasses = [
  "inline-flex min-h-12 cursor-pointer items-center justify-center gap-2 border-2",
  "px-5 py-3 text-sm font-black uppercase tracking-wider outline-none",
  "transition-[transform,box-shadow,background-color,border-color,color] duration-150 ease-out",
  "focus-visible:outline-2 focus-visible:outline-[var(--accent)] focus-visible:outline-offset-2",
  "enabled:active:translate-x-0 enabled:active:translate-y-0 enabled:active:shadow-none",
  "disabled:cursor-not-allowed disabled:opacity-40",
  "motion-reduce:transform-none motion-reduce:transition-none",
].join(" ");

const buttonVariants = {
  primary:
    "border-[var(--accent)] bg-[var(--accent)] text-[var(--bg)] shadow-[4px_4px_0px_0px_var(--text)] enabled:hover:-translate-x-0.5 enabled:hover:-translate-y-0.5 enabled:hover:shadow-[6px_6px_0px_0px_var(--text)]",
  secondary:
    "border-white/20 bg-transparent text-[var(--text)] shadow-[4px_4px_0px_0px_rgba(255,255,255,0.1)] enabled:hover:-translate-x-0.5 enabled:hover:-translate-y-0.5 enabled:hover:border-white/40 enabled:hover:shadow-[6px_6px_0px_0px_rgba(255,255,255,0.15)]",
  ghost:
    "border-transparent bg-transparent text-[var(--muted)] shadow-none enabled:hover:text-[var(--accent)]",
  danger:
    "border-[var(--red)] bg-[var(--red)]/10 text-[var(--red)] shadow-[4px_4px_0px_0px_var(--red)] enabled:hover:-translate-x-0.5 enabled:hover:-translate-y-0.5 enabled:hover:shadow-[6px_6px_0px_0px_var(--red)]",
};

export function Input({
  className = "",
  ...props
}: ComponentPropsWithRef<"input">) {
  return (
    <input
      {...props}
      className={`ui-control ${controlClasses} file:mr-4 file:cursor-pointer file:border-2 file:border-white/20 file:bg-[var(--panel)] file:px-3 file:py-1.5 file:text-xs file:font-black file:uppercase file:text-[var(--text)] file:transition-colors hover:file:bg-white/10 ${className}`}
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
          className="pointer-events-none absolute top-1/2 right-4 size-4 -translate-y-1/2 text-[var(--muted)] transition-colors duration-150 peer-focus:text-[var(--accent)] peer-disabled:opacity-40 motion-reduce:transition-none"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="square"
          strokeLinejoin="miter"
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
        className={`${toggleClasses} indeterminate:border-[var(--accent)] indeterminate:bg-[var(--accent)] ${className}`}
      />
      <svg
        className="pointer-events-none absolute inset-0 m-auto size-3.5 text-[var(--bg)] opacity-0 transition-opacity duration-150 peer-checked:opacity-100 peer-indeterminate:hidden motion-reduce:transition-none"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="3.5"
        strokeLinecap="square"
        strokeLinejoin="miter"
        aria-hidden="true"
        focusable="false"
      >
        <path d="m5 12 4 4L19 6" />
      </svg>
      <span
        className="pointer-events-none absolute inset-0 m-auto h-1 w-2.5 bg-[var(--bg)] opacity-0 transition-opacity duration-150 peer-indeterminate:opacity-100 motion-reduce:transition-none"
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
        className={`${toggleClasses} ${className}`}
      />
      <span
        className="pointer-events-none absolute inset-0 m-auto size-2 bg-[var(--bg)] opacity-0 transition-opacity duration-150 peer-checked:opacity-100 motion-reduce:transition-none"
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
        <div className="artwork-placeholder !bg-[var(--panel)] !bg-none">
          <svg viewBox="0 0 32 32" aria-hidden="true" className="stroke-[var(--subtle)] stroke-2 fill-none">
            <rect x="4" y="3" width="24" height="26" />
            <path d="M4 10h24M4 22h24M11 3v7m10-7v7M11 22v7m10-7v7" />
          </svg>
          <UserIcon className="avatar-placeholder-icon" aria-hidden="true" />
          <span className="font-mono text-[10px] uppercase tracking-widest">Нет изображения</span>
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
  
  const ratingValue = rating ?? cardMedia.vote_average ?? cardMedia.avg_rating;

  return (
    <Link href={mediaHref(cardMedia)} className="media-card group !rounded-none !border-2 !border-white/20 !shadow-[6px_6px_0px_0px_rgba(255,255,255,0.05)] hover:!-translate-x-1 hover:!-translate-y-1 hover:!scale-100 hover:!border-[var(--accent)] hover:!shadow-[8px_8px_0px_0px_var(--accent)]">
      <div className="poster-wrap !rounded-none">
        <Artwork
          src={cardMedia.poster_url || cardMedia.poster_key}
          alt={cardMedia.title_ru}
        />
        {ratingValue ? (
          <span className="absolute z-10 top-2 left-2 inline-flex items-center gap-1 border-2 border-[var(--bg)] bg-[var(--accent)] px-2 py-0.5 font-mono text-xs font-black uppercase text-[var(--bg)] shadow-[3px_3px_0px_0px_var(--text)]">
            <StarIcon className="size-3" aria-hidden="true" />
            {Number(ratingValue).toFixed(1)}
          </span>
        ) : null}
        <span className="poster-preview !bg-[var(--bg)] !border-2 !border-[var(--accent)] !text-[var(--accent)] !rounded-none !px-2 !py-1 !font-mono !text-[10px] !uppercase !tracking-widest" aria-hidden="true">
          Открыть
          <ArrowRightIcon className="ui-icon" />
        </span>
      </div>
      <h3 className="!font-black !uppercase !tracking-tight !text-sm">{cardMedia.title_ru}</h3>
      <div className="media-meta !font-mono !text-[10px] !uppercase !tracking-widest">
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
      <span className="spinner !border-2 !border-white/20 !border-t-[var(--accent)] !rounded-none" />
      <span className="font-mono text-xs uppercase tracking-widest">{text}</span>
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
    <div className="notice error !border-2 !border-[var(--red)] !border-l-4 !bg-[var(--red)]/10 !rounded-none" role="alert">
      <p className="!font-mono !text-sm">{errorMessage(error)}</p>
      {retry && (
        <button className="button secondary !mt-4" onClick={retry}>
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
    <div className="empty-state panel !bg-[var(--panel)] !border-2 !border-white/20 !shadow-[8px_8px_0px_0px_var(--accent)] !rounded-none">
      <span className="empty-icon !bg-[var(--accent)] !text-[var(--bg)] !border-2 !border-[var(--bg)] !rounded-none !shadow-[4px_4px_0px_0px_var(--text)]">
        <BookmarkSquareIcon aria-hidden="true" />
      </span>
      <h2 className="!font-black !uppercase !tracking-tight">{title}</h2>
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
        {eyebrow && <span className="eyebrow !text-[var(--accent)] !font-mono !tracking-widest">{eyebrow}</span>}
        <h1 className="!font-black !uppercase !tracking-tighter">{title}</h1>
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
      <span className="!font-mono !text-xs !uppercase !tracking-widest !text-[var(--muted)]">{label}</span>
      {children}
      {hint && <small className="!font-mono !uppercase">{hint}</small>}
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
      <span className="!font-mono !text-xs !uppercase !tracking-widest">
        {page} / {last} <small className="!text-[var(--subtle)]">· Всего {total}</small>
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
      className="modal panel !bg-[var(--bg)] !border-2 !border-white/20 !shadow-[16px_16px_0px_0px_var(--accent)] !rounded-none"
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        if (event.target === ref.current) onClose();
      }}
    >
      <div className="modal-heading">
        <h2 className="!font-black !uppercase !tracking-tight">{title}</h2>
        <button className="icon-button !border-2 !border-white/20 !bg-[var(--bg)] !rounded-none hover:!bg-[var(--accent)] hover:!text-[var(--bg)]" onClick={onClose} aria-label="Закрыть">
          <XMarkIcon className="ui-icon" aria-hidden="true" />
        </button>
      </div>
      {children}
    </dialog>
  );
}