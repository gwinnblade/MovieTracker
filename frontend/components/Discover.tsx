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
        eyebrow="ПУСТЬ КИНО ВЫБЕРЕТ ТЕБЯ"
        title="Случайный фильм"
        description="Выберем историю из проверенного каталога сообщества."
      />

      <section className="relative mx-auto max-w-[850px] overflow-hidden rounded-2xl border border-white/5 bg-[#151921]/80 p-6 shadow-[0_0_60px_rgba(229,169,61,0.04)] backdrop-blur-md sm:p-8">
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-gold/50 to-transparent"
          aria-hidden="true"
        />
        <div
          className="pointer-events-none absolute -top-28 -right-20 size-64 rounded-full bg-gold/5 blur-3xl"
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
            className="group min-h-14! w-full bg-gradient-to-r from-gold to-gold-hover px-8! py-4! text-base! transition-all! hover:shadow-[0_0_20px_rgba(229,169,61,0.4)]! sm:w-auto sm:self-start"
          >
            <ArrowPathIcon
              className={`ui-icon ${
                busy
                  ? "animate-spin"
                  : "transition-transform duration-500 group-hover:rotate-180"
              }`}
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
          <div className="random-card relative gap-8">
            <div
              className="pointer-events-none absolute top-8 left-0 h-48 w-56 rounded-full bg-gold/5 blur-3xl"
              aria-hidden="true"
            />
            <Artwork
              className="rounded-2xl! shadow-[0_30px_60px_-15px_rgba(0,0,0,0.8)]!"
              src={media.poster_url || media.poster_key}
              alt={media.title_ru}
            />
            <div className="relative min-w-0">
              <span className="eyebrow">ВОТ ТВОЯ ИСТОРИЯ</span>
              <h2 className="text-3xl! font-bold! tracking-tight! text-white">
                {media.title_ru}
              </h2>
              <p className="mt-3! flex flex-wrap items-center gap-2 text-xs text-zinc-500">
                <span>{media.release_date?.slice(0, 4)}</span>
                <span
                  className="size-1 rounded-full bg-zinc-600"
                  aria-hidden="true"
                />
                <span>{media.type?.name_ru}</span>
              </p>
              <p className="description mt-4! leading-relaxed! text-zinc-400!">
                {media.description_ru}
              </p>
              <div className="form-actions mt-6!">
                <Link
                  className="button group w-full bg-gradient-to-r from-gold to-gold-hover sm:w-auto"
                  href={mediaHref(media)}
                >
                  Открыть карточку{" "}
                  <ArrowRightIcon
                    className="ui-icon transition-transform duration-200 group-hover:translate-x-0.5"
                    aria-hidden="true"
                  />
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
        className="group inline-flex items-center gap-2 text-sm text-zinc-400! transition-colors duration-200 hover:text-gold!"
      >
        <ArrowLeftIcon
          className="ui-icon transition-transform duration-200 group-hover:-translate-x-0.5"
          aria-hidden="true"
        />{" "}
        Каталог
      </Link>

      <div className="relative mt-8 flex flex-wrap items-center gap-8 overflow-hidden rounded-3xl border border-white/5 bg-gradient-to-br from-[#151921] to-[#0B0E14] p-6 shadow-[0_24px_70px_rgba(0,0,0,0.45)] sm:p-8">
        <div
          className="pointer-events-none absolute -top-24 -right-16 size-72 rounded-full bg-gold/10 blur-3xl"
          aria-hidden="true"
        />
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-gold/50 to-transparent"
          aria-hidden="true"
        />
        <Artwork
          className="avatar relative size-28! shrink-0 rounded-full! border-2! border-gold/30! shadow-[0_0_30px_rgba(229,169,61,0.2)]! sm:size-32!"
          src={person.photo_url}
          alt={person.name}
        />
        <div className="relative min-w-0 flex-1">
          <span className="eyebrow">ЛИЦА КИНО</span>
          <h1 className="mt-2! text-4xl! font-bold! tracking-tight! text-white">
            {person.name}
          </h1>
          <p className="mt-2! text-sm text-zinc-400">
            Фильмография в каталоге сообщества
          </p>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-gold/25 bg-gold/10 px-3 py-1 text-xs font-semibold text-gold">
              <FilmIcon className="size-3.5" aria-hidden="true" />
              {person.filmography.length} работ
            </span>
          </div>
        </div>
      </div>

      <section className="mt-10">
        <div className="mb-6 flex items-center gap-4">
          <h2 className="text-2xl! font-bold! tracking-tight! text-white">
            Фильмография
          </h2>
          <span
            className="h-px flex-1 bg-gradient-to-r from-white/10 to-transparent"
            aria-hidden="true"
          />
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