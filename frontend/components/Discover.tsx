"use client";
import {
  ArrowLeftIcon,
  ArrowPathIcon,
  ArrowRightIcon,
  FilmIcon,
} from "@heroicons/react/24/outline";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, mediaHref } from "@/lib/api";
import type { Media } from "@/lib/types";
import {
  Artwork,
  Button,
  Empty,
  ErrorState,
  Field,
  Loading,
  MediaCard,
  PageHeading,
  Select,
} from "./UI";

export function Random() {
  const [type, setType] = useState("");
  const [genre, setGenre] = useState("");
  const [media, setMedia] = useState<Media | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const types = useQuery({
    queryKey: ["types"],
    queryFn: () => api.references("types"),
  });
  const genres = useQuery({
    queryKey: ["genres"],
    queryFn: () => api.references("genres"),
  });

  const roll = async () => {
    setBusy(true);
    setError(null);
    try {
      setMedia(
        await api.random({
          type_id: type || undefined,
          genre_id: genre || undefined,
        }),
      );
    } catch (error) {
      setError(error);
      setMedia(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeading
        eyebrow="[ ПУСТЬ КИНО ВЫБЕРЕТ ТЕБЯ ]"
        title="Случайный фильм"
        description="Выберем историю из проверенного каталога сообщества."
      />

      <section className="relative mx-auto max-w-[850px] border-2 border-white/10 bg-[var(--panel)] p-6 shadow-[8px_8px_0px_0px_var(--accent)] sm:p-8">
        {/* Solid accent rule — ticket stub edge */}
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-1 bg-[var(--accent)]"
          aria-hidden="true"
        />

        <form
          className="form-stack relative"
          onSubmit={(event) => {
            event.preventDefault();
            void roll();
          }}
        >
          <div className="form-row">
            <Field label="Тип">
              <Select
                value={type}
                onChange={(event) => setType(event.target.value)}
              >
                <option value="">Любой</option>
                {types.data?.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name_ru}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Жанр">
              <Select
                value={genre}
                onChange={(event) => setGenre(event.target.value)}
              >
                <option value="">Любой</option>
                {genres.data?.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name_ru}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <Button
            variant="primary"
            disabled={busy}
            className="group min-h-14! w-full px-8! py-4! text-sm! sm:w-auto sm:self-start"
          >
            <ArrowPathIcon
              className={`ui-icon ${busy ? "animate-spin" : ""}`}
              aria-hidden="true"
            />
            {busy ? "Выбираем…" : "Найти случайный фильм"}
          </Button>
        </form>

        {error ? (
          <div className="mt-6">
            <ErrorState error={error} />
          </div>
        ) : media ? (
          <div className="random-card relative mt-6 border-t-2 border-white/10 pt-6">
            <Artwork
              className="border-2 border-white/20 shadow-[12px_12px_0px_0px_var(--accent)]"
              src={media.poster_url || media.poster_key}
              alt={media.title_ru}
            />
            <div className="relative min-w-0">
              <span className="inline-block border-2 border-[var(--accent)] bg-[var(--accent)] px-3 py-1 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)]">
                [ Вот твоя история ]
              </span>
              <h2 className="mt-4 text-3xl font-black uppercase leading-[1.05] tracking-tighter text-[var(--text)] sm:text-4xl">
                {media.title_ru}
              </h2>
              <p className="mt-3 flex flex-wrap items-center gap-2 font-mono text-[11px] uppercase tracking-widest text-[var(--subtle)]">
                <span>{media.release_date?.slice(0, 4)}</span>
                <span className="h-1 w-1 bg-[var(--subtle)]" aria-hidden="true" />
                <span>{media.type?.name_ru}</span>
              </p>
              <p className="description mt-4 max-w-2xl leading-relaxed text-[var(--muted)]">
                {media.description_ru}
              </p>
              <div className="form-actions mt-6">
                <Link
                  className="button group w-full sm:w-auto"
                  href={mediaHref(media)}
                >
                  Открыть карточку{" "}
                  <ArrowRightIcon className="ui-icon" aria-hidden="true" />
                </Link>
              </div>
            </div>
          </div>
        ) : (
          !busy && (
            <div className="mt-6">
              <Empty title="Что-то неожиданное">
                <p>Нажми кнопку, чтобы выбрать фильм на вечер.</p>
              </Empty>
            </div>
          )
        )}
      </section>
    </>
  );
}

export function PersonPage() {
  const params = useParams<{ id: string }>();
  const data = useQuery({
    queryKey: ["person", params.id],
    queryFn: () => api.person(Number(params.id)),
  });

  if (data.isPending) return <Loading />;
  if (data.error)
    return <ErrorState error={data.error} retry={() => data.refetch()} />;

  const person = data.data;

  return (
    <>
      <Link
        href="/library"
        className="group inline-flex items-center gap-2 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--muted)] hover:text-[var(--accent)]"
      >
        <ArrowLeftIcon className="ui-icon" aria-hidden="true" />
        Каталог
      </Link>

      <div className="relative mt-8 flex flex-wrap items-center gap-8 border-2 border-white/10 bg-[var(--panel)] p-6 shadow-[10px_10px_0px_0px_var(--accent)] sm:p-8">
        {/* Solid accent rule — ticket stub edge */}
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-1 bg-[var(--accent)]"
          aria-hidden="true"
        />

        <Artwork
          className="avatar size-28! shrink-0 border-2 border-white/20 sm:size-32!"
          src={person.photo_url}
          alt={person.name}
        />

        <div className="relative min-w-0 flex-1">
          <span className="inline-block border-2 border-[var(--accent)] bg-[var(--accent)] px-3 py-1 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)]">
            [ Лица кино ]
          </span>
          <h1 className="mt-4 text-4xl font-black uppercase leading-[1.05] tracking-tighter text-[var(--text)] sm:text-5xl">
            {person.name}
          </h1>
          <p className="mt-2 text-sm text-[var(--muted)]">
            Фильмография в каталоге сообщества
          </p>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 border-2 border-[var(--bg)] bg-[var(--accent)] px-3 py-1 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)] shadow-[2px_2px_0px_0px_var(--text)]">
              <FilmIcon className="size-3.5" aria-hidden="true" />
              {person.filmography.length} работ
            </span>
          </div>
        </div>
      </div>

      <section className="mt-10">
        <div className="mb-6 flex items-center gap-4 border-b-2 border-white/10 pb-4">
          <h2 className="text-2xl font-black uppercase tracking-tight text-[var(--text)]">
            Фильмография
          </h2>
        </div>
        <div className="media-grid">
          {person.filmography.map((media) => (
            <MediaCard
              key={`${media.id}-${media.pivot.role_name_ru}`}
              media={media}
              caption={[media.pivot.role_name_ru, media.pivot.character]
                .filter(Boolean)
                .join(" · ")}
            />
          ))}
        </div>
      </section>
    </>
  );
}