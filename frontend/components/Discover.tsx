"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, mediaHref } from "@/lib/api";
import type { Media } from "@/lib/types";
import {
  Artwork,
  Empty,
  ErrorState,
  Field,
  Loading,
  MediaCard,
  PageHeading,
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
      <section className="random-panel panel">
        <form
          className="form-stack"
          onSubmit={(event) => {
            event.preventDefault();
            void roll();
          }}
        >
          <div className="form-row">
            <Field label="Тип">
              <select
                value={type}
                onChange={(event) => setType(event.target.value)}
              >
                <option value="">Любой</option>
                {types.data?.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name_ru}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Жанр">
              <select
                value={genre}
                onChange={(event) => setGenre(event.target.value)}
              >
                <option value="">Любой</option>
                {genres.data?.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name_ru}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <button className="button" disabled={busy}>
            {busy ? "Выбираем…" : "↻ Найти случайный фильм"}
          </button>
        </form>
        {error ? (
          <ErrorState error={error} />
        ) : media ? (
          <div className="random-card">
            <Artwork
              src={media.poster_url || media.poster_key}
              alt={media.title_ru}
            />
            <div>
              <span className="eyebrow">ВОТ ТВОЯ ИСТОРИЯ</span>
              <h2>{media.title_ru}</h2>
              <p className="detail-meta">
                {media.release_date?.slice(0, 4)} · {media.type?.name_ru}
              </p>
              <p className="description">{media.description_ru}</p>
              <div className="form-actions">
                <Link className="button" href={mediaHref(media)}>
                  Открыть карточку →
                </Link>
              </div>
            </div>
          </div>
        ) : (
          !busy && (
            <Empty title="Что-то неожиданное">
              <p>Нажми кнопку, чтобы выбрать фильм на вечер.</p>
            </Empty>
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
      <Link href="/library">← Каталог</Link>
      <div className="profile-header panel section">
        <Artwork className="avatar" src={person.photo_url} alt={person.name} />
        <div>
          <span className="eyebrow">ЛИЦА КИНО</span>
          <h1>{person.name}</h1>
          <p>Фильмография в каталоге сообщества</p>
        </div>
      </div>
      <section className="section">
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
