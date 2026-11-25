"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { api, errorMessage } from "@/lib/api";
import type { Entry, Media, Person } from "@/lib/types";
import { useAuth } from "./Auth";
import {
  Artwork,
  Empty,
  ErrorState,
  Field,
  Loading,
  MediaGrid,
  Modal,
} from "./UI";
import SeasonTracker from "./SeasonTracker";

export default function Detail({ external = false }: { external?: boolean }) {
  const params = useParams<{
    id: string;
    media_type: string;
    tmdb_id: string;
  }>();
  const { user } = useAuth();
  const identity = external
    ? `${params.media_type}:${params.tmdb_id}`
    : params.id;
  return (
    <DetailContent
      key={identity}
      external={external}
      id={Number(external ? params.tmdb_id : params.id)}
      type={params.media_type}
      userId={user?.id}
    />
  );
}

function DetailContent({
  external,
  id,
  type,
  userId,
}: {
  external: boolean;
  id: number;
  type?: string;
  userId?: number;
}) {
  const cache = useQueryClient();
  const [saved, setSaved] = useState<Media | null>(null);
  const [picker, setPicker] = useState(false);
  const data = useQuery({
    queryKey: ["detail", external, type, id],
    queryFn: () =>
      external ? api.tmdbDetails(type || "movie", id) : api.media(id),
  });
  const media = data.data;
  const localId = saved?.id || media?.id;
  const tracking = useQuery({
    queryKey: ["tracking", userId, localId],
    queryFn: () => api.tracking(localId!),
    enabled: !!userId && !!localId,
  });
  const similar = useQuery({
    queryKey: ["similar", localId],
    queryFn: () => api.similar(localId!),
    enabled: !!localId && media?.moderation_status === "approved",
  });
  const ensureLocal = async (): Promise<Media> => {
    if (!media) throw new Error("Карточка ещё загружается.");
    if (localId) return { ...media, id: localId };
    if (!media.tmdb_id || !media.tmdb_type)
      throw new Error("Не удалось сохранить запись.");
    const record = await api.saveTmdb(media.tmdb_type, media.tmdb_id);
    setSaved(record);
    return record;
  };
  const invalidate = async () => {
    await Promise.all([
      cache.invalidateQueries({ queryKey: ["tracking"] }),
      cache.invalidateQueries({ queryKey: ["entries"] }),
      cache.invalidateQueries({ queryKey: ["profile"] }),
      cache.invalidateQueries({ queryKey: ["browse"] }),
    ]);
  };
  if (data.isPending) return <Loading text="Открываем историю…" />;
  if (data.error || !media)
    return <ErrorState error={data.error} retry={() => data.refetch()} />;
  const localPeople = media.persons || [];
  const directors = localPeople.filter((person) =>
    person.roles?.some((role) => role.code === "director"),
  );
  const cast = localPeople.filter((person) =>
    person.roles?.some((role) => role.code === "cast" || role.code === "actor"),
  );
  const isSeries = media.tmdb_type === "tv" || media.type?.code === "series";
  const suggestHref =
    media.moderation_status === "approved" && localId
      ? "/suggest?media_id=" + localId
      : `/suggest?tmdb_id=${media.tmdb_id || ""}&type=${media.tmdb_type || "movie"}`;
  return (
    <>
      <Link
        href={media.moderation_status === "approved" ? "/library" : "/catalog"}
      >
        ← Вернуться к кино
      </Link>
      <div className="detail-grid">
        <aside className="detail-poster">
          <Artwork
            src={media.poster_url || media.poster_key}
            alt={media.title_ru}
            priority
          />
          {userId ? (
            <button
              className="button secondary"
              onClick={() => setPicker(true)}
            >
              + В коллекцию
            </button>
          ) : (
            <Link
              className="button"
              href={
                "/login?next=" +
                encodeURIComponent(
                  external ? `/title/${type}/${id}` : `/media/${id}`,
                )
              }
            >
              Войти и сохранить
            </Link>
          )}
          <Link className="button secondary" href={suggestHref}>
            {media.moderation_status === "approved"
              ? "Предложить исправление"
              : "Предложить в каталог"}
          </Link>
        </aside>
        <div className="detail-content">
          <span className="eyebrow">
            {isSeries ? "СЕРИАЛ" : media.type?.name_ru || "ФИЛЬМ"}
          </span>
          <h1>{media.title_ru}</h1>
          {media.title_en && media.title_en !== media.title_ru && (
            <p className="original-title">{media.title_en}</p>
          )}
          <div className="detail-meta">
            {media.release_date && (
              <span className="pill">{media.release_date.slice(0, 4)}</span>
            )}
            {!!media.vote_average && (
              <span className="pill">
                ★ TMDB {media.vote_average.toFixed(1)}
              </span>
            )}
            {!!media.runtime && (
              <span className="pill">{media.runtime} мин.</span>
            )}
            {!!media.number_of_episodes && (
              <span className="pill">{media.number_of_episodes} серий</span>
            )}
            {media.moderation_status === "approved" && (
              <span className="pill green">В каталоге сообщества</span>
            )}
          </div>
          <div className="genre-list">
            {media.genres?.map((genre) => (
              <span className="pill" key={genre.id || genre.name_ru}>
                {genre.name_ru}
              </span>
            ))}
          </div>
          <p className="description">
            {media.description_ru || "Описание пока отсутствует."}
          </p>
          {media.tmdb_failed_at && (
            <div className="notice">
              Не удалось обновить данные TMDB. Твои сохранённые записи доступны.
            </div>
          )}
          <div className="credit-row">
            <span>Режиссёр / создатель:</span>
            {(directors.length
              ? directors
              : media.directors || (media.director ? [media.director] : [])
            ).map((person) =>
              person.id ? (
                <Link href={"/persons/" + person.id} key={person.id}>
                  {person.name}
                </Link>
              ) : (
                <span key={person.tmdb_id || person.name}>{person.name}</span>
              ),
            )}
          </div>
          {!!media.companies?.length && (
            <div className="credit-row">
              <span>Производство:</span>
              <span>
                {media.companies.map((company) => company.name).join(", ")}
              </span>
            </div>
          )}
          {userId &&
            (tracking.isPending && localId ? (
              <Loading text="Загрузка твоей записи…" />
            ) : tracking.error ? (
              <ErrorState
                error={tracking.error}
                retry={() => tracking.refetch()}
              />
            ) : (
              <EntryEditor
                key={tracking.data?.entry?.updated_at || "new"}
                entry={tracking.data?.entry || null}
                ensureLocal={ensureLocal}
                onSaved={invalidate}
              />
            ))}
          {!!(cast.length || media.cast?.length) && (
            <section className="section">
              <h2>В ролях</h2>
              <div className="people-grid">
                {(cast.length ? cast : media.cast || []).map((person) => (
                  <PersonCard
                    key={person.id || person.tmdb_id || person.name}
                    person={person}
                  />
                ))}
              </div>
            </section>
          )}
          {isSeries && (
            <SeasonTracker
              media={{ ...media, id: localId }}
              tracking={tracking.data}
              userId={userId}
              ensureLocal={ensureLocal}
              onSaved={invalidate}
            />
          )}
          {!!similar.data?.movies.length && (
            <section className="section">
              <div className="section-heading">
                <h2>Ещё у этого режиссёра</h2>
                {similar.data.director?.id && (
                  <Link href={"/persons/" + similar.data.director.id}>
                    Фильмография →
                  </Link>
                )}
              </div>
              <MediaGrid items={similar.data.movies} />
            </section>
          )}
        </div>
      </div>
      {picker && (
        <CollectionPicker
          ensureLocal={ensureLocal}
          onClose={() => setPicker(false)}
        />
      )}
    </>
  );
}

function PersonCard({ person }: { person: Person }) {
  const content = (
    <>
      <Artwork src={person.photo_url} alt={person.name} />
      <p>{person.name}</p>
      <small>{person.pivot?.character || person.character}</small>
    </>
  );
  return person.id ? (
    <Link className="person-card" href={"/persons/" + person.id}>
      {content}
    </Link>
  ) : (
    <div className="person-card">{content}</div>
  );
}

function EntryEditor({
  entry,
  ensureLocal,
  onSaved,
}: {
  entry: Entry | null;
  ensureLocal: () => Promise<Media>;
  onSaved: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const statuses = useQuery({
    queryKey: ["statuses"],
    queryFn: () => api.references("statuses"),
  });
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    try {
      const media = await ensureLocal();
      await api.saveEntry({
        media_id: media.id!,
        status_id: Number(form.get("status")),
        rating: form.get("rating") ? Number(form.get("rating")) : null,
        note: String(form.get("note") || ""),
        date: String(form.get("date") || "") || null,
      });
      await onSaved();
      toast.success("Твоя запись сохранена");
    } catch (error) {
      toast.error(errorMessage(error));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="tracking-panel panel">
      <h2>{entry ? "Твоя запись" : "Добавить в мой список"}</h2>
      {statuses.isPending ? (
        <Loading />
      ) : statuses.error ? (
        <ErrorState error={statuses.error} />
      ) : (
        <form onSubmit={submit} className="form-stack">
          <div className="form-row">
            <Field label="Статус просмотра">
              <select
                name="status"
                defaultValue={
                  entry?.status_id ||
                  statuses.data?.find((status) => status.code === "planned")?.id
                }
                required
              >
                {statuses.data?.map((status) => (
                  <option key={status.id} value={status.id}>
                    {status.name_ru}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Твоя оценка">
              <select name="rating" defaultValue={entry?.rating || ""}>
                <option value="">Без оценки</option>
                {Array.from({ length: 10 }, (_, index) => (
                  <option key={index} value={index + 1}>
                    {index + 1} / 10
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <Field label="Дата просмотра">
            <input
              type="date"
              name="date"
              defaultValue={entry?.date?.slice(0, 10) || ""}
            />
          </Field>
          <Field label="Заметка для себя">
            <textarea
              name="note"
              defaultValue={entry?.note || ""}
              maxLength={5000}
              placeholder="Что запомнилось?"
            />
          </Field>
          <div className="form-actions">
            <button className="button" disabled={busy}>
              {busy ? "Сохраняем…" : "Сохранить запись"}
            </button>
            {entry && <Link href="/entries">Перейти к моему списку →</Link>}
          </div>
        </form>
      )}
    </section>
  );
}

function CollectionPicker({
  ensureLocal,
  onClose,
}: {
  ensureLocal: () => Promise<Media>;
  onClose: () => void;
}) {
  const { user } = useAuth();
  const cache = useQueryClient();
  const [busy, setBusy] = useState(false);
  const lists = useQuery({
    queryKey: ["collections", user?.id],
    queryFn: api.collections,
  });
  return (
    <Modal title="Добавить в коллекцию" onClose={onClose}>
      {lists.isPending ? (
        <Loading />
      ) : lists.error ? (
        <ErrorState error={lists.error} />
      ) : lists.data.length ? (
        <div className="modal-list">
          {lists.data.map((list) => (
            <button
              className="button secondary"
              disabled={busy}
              key={list.id}
              onClick={async () => {
                setBusy(true);
                try {
                  const media = await ensureLocal();
                  await api.addToCollection(list.id, media.id!);
                  await cache.invalidateQueries({ queryKey: ["collections"] });
                  await cache.invalidateQueries({ queryKey: ["collection"] });
                  toast.success("Добавлено в коллекцию");
                  onClose();
                } catch (error) {
                  toast.error(errorMessage(error));
                } finally {
                  setBusy(false);
                }
              }}
            >
              <span>{list.name}</span>
              <small>{list.media_count} записей</small>
            </button>
          ))}
        </div>
      ) : (
        <Empty title="Пока нет коллекций">
          <Link className="button" href="/collections">
            Создать коллекцию
          </Link>
        </Empty>
      )}
    </Modal>
  );
}
