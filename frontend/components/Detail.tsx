"use client";
import {
  ArrowLeftIcon,
  ArrowRightIcon,
  BuildingOffice2Icon,
  CheckBadgeIcon,
  ExclamationTriangleIcon,
  PlusIcon,
  VideoCameraIcon,
} from "@heroicons/react/24/outline";
import { StarIcon } from "@heroicons/react/24/solid";
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
  Button,
  Empty,
  ErrorState,
  Field,
  Input,
  Loading,
  MediaGrid,
  Modal,
  Select,
  Textarea,
} from "./UI";
import SeasonTracker from "./SeasonTracker";

const metaBadge =
  "inline-flex items-center border-2 border-white/20 bg-white/5 px-2 py-0.5 font-mono text-[10px] font-black uppercase tracking-widest text-[var(--muted)]";

const ratingBadge =
  "inline-flex items-center gap-1 border-2 border-[var(--bg)] bg-[var(--accent)] px-2 py-0.5 font-mono text-[10px] font-black uppercase tracking-widest text-[var(--bg)] shadow-[2px_2px_0px_0px_var(--text)]";

const approvedBadge =
  "inline-flex items-center gap-1 border-2 border-[var(--bg)] bg-[var(--green)] px-2 py-0.5 font-mono text-[10px] font-black uppercase tracking-widest text-[var(--bg)]";

const genreBadge =
  "inline-flex items-center border-2 border-[var(--accent)] bg-transparent px-2 py-0.5 font-mono text-[10px] font-black uppercase tracking-widest text-[var(--accent)]";

const sectionStamp =
  "inline-block border-2 border-[var(--accent)] bg-[var(--accent)] px-3 py-1 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)]";

const quietLink =
  "font-mono text-[11px] font-black uppercase tracking-widest text-[var(--muted)] hover:text-[var(--accent)]";

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
        className="group inline-flex items-center gap-2 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--muted)] hover:text-[var(--accent)]"
      >
        <ArrowLeftIcon className="ui-icon" aria-hidden="true" />
        Вернуться к кино
      </Link>

      <div className="detail-grid">
        <aside className="detail-poster">
          <div className="relative">
            <Artwork
              className="relative border-2 border-white/20 shadow-[12px_12px_0px_0px_var(--accent)]"
              src={media.poster_url || media.poster_key}
              alt={media.title_ru}
              priority
            />
          </div>
          <div className="mt-4 flex flex-col gap-3">
            {userId ? (
              <Button
                variant="primary"
                className="group w-full"
                onClick={() => setPicker(true)}
              >
                <PlusIcon className="ui-icon" aria-hidden="true" />
                В коллекцию
              </Button>
            ) : (
              <Link
                className="button mt-0! w-full"
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
            <Link className="button secondary mt-0! w-full" href={suggestHref}>
              {media.moderation_status === "approved"
                ? "Предложить исправление"
                : "Предложить в каталог"}
            </Link>
          </div>
        </aside>

        <div className="detail-content">
          <span className="inline-block border-2 border-[var(--accent)] bg-[var(--accent)] px-3 py-1 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)]">
            {isSeries ? "Сериал" : media.type?.name_ru || "Фильм"}
          </span>

          <h1 className="mt-4 text-4xl font-black uppercase leading-[1.05] tracking-tighter text-[var(--text)] sm:text-5xl md:text-6xl">
            {media.title_ru}
          </h1>

          {media.title_en && media.title_en !== media.title_ru && (
            <p className="mt-2 font-mono text-sm uppercase tracking-widest text-[var(--subtle)]">
              {media.title_en}
            </p>
          )}

          <div className="detail-meta mt-6 flex flex-wrap items-center gap-2">
            {media.release_date && (
              <span className={metaBadge}>{media.release_date.slice(0, 4)}</span>
            )}
            {!!media.vote_average && (
              <span className={ratingBadge}>
                <StarIcon className="size-3" aria-hidden="true" /> TMDB{" "}
                {media.vote_average.toFixed(1)}
              </span>
            )}
            {!!media.runtime && (
              <span className={metaBadge}>{media.runtime} мин.</span>
            )}
            {!!media.number_of_episodes && (
              <span className={metaBadge}>
                {media.number_of_episodes} серий
              </span>
            )}
            {media.moderation_status === "approved" && (
              <span className={approvedBadge}>
                <CheckBadgeIcon className="size-3" aria-hidden="true" /> В
                каталоге
              </span>
            )}
          </div>

          <div className="genre-list mt-5 flex flex-wrap gap-2">
            {media.genres?.map((genre) => (
              <span className={genreBadge} key={genre.id || genre.name_ru}>
                {genre.name_ru}
              </span>
            ))}
          </div>

          <p className="description mt-8 max-w-3xl text-[var(--muted)] leading-relaxed">
            {media.description_ru || "Описание пока отсутствует."}
          </p>

          {media.tmdb_failed_at && (
            <div className="notice mt-5 flex items-start gap-3">
              <ExclamationTriangleIcon
                className="ui-icon mt-0.5 shrink-0"
                aria-hidden="true"
              />
              <span>
                Не удалось обновить данные TMDB. Твои сохранённые записи
                доступны.
              </span>
            </div>
          )}

          <div className="credit-row mt-6 flex flex-wrap items-center gap-2 border-t-2 border-white/10 pt-4">
            <VideoCameraIcon
              className="size-4 text-[var(--accent)]"
              aria-hidden="true"
            />
            <span className="font-mono text-[11px] uppercase tracking-widest text-[var(--subtle)]">
              Режиссёр / создатель:
            </span>
            {(directors.length
              ? directors
              : media.directors || (media.director ? [media.director] : [])
            ).map((person) =>
              person.id ? (
                <Link
                  href={"/persons/" + person.id}
                  key={person.id}
                  className={quietLink}
                >
                  {person.name}
                </Link>
              ) : (
                <span
                  className="font-mono text-[11px] uppercase tracking-widest text-[var(--muted)]"
                  key={person.tmdb_id || person.name}
                >
                  {person.name}
                </span>
              ),
            )}
          </div>

          {!!media.companies?.length && (
            <div className="credit-row flex flex-wrap items-center gap-2 border-t-2 border-white/10 pt-4">
              <BuildingOffice2Icon
                className="size-4 text-[var(--subtle)]"
                aria-hidden="true"
              />
              <span className="font-mono text-[11px] uppercase tracking-widest text-[var(--subtle)]">
                Производство:
              </span>
              <span className="font-mono text-[11px] uppercase tracking-widest text-[var(--muted)]">
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
            <section className="section mt-10">
              <div className="mb-6 flex items-center gap-3 border-b-2 border-white/10 pb-4">
                <span className={sectionStamp}>В ролях</span>
              </div>
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
            <section className="section mt-10">
              <div className="section-heading mb-6 border-b-2 border-white/10 pb-4">
                <span className={sectionStamp}>Ещё у этого режиссёра</span>
                {similar.data.director?.id && (
                  <Link
                    href={"/persons/" + similar.data.director.id}
                    className="group inline-flex items-center gap-2 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--muted)] hover:text-[var(--accent)]"
                  >
                    Фильмография
                    <ArrowRightIcon className="ui-icon" aria-hidden="true" />
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
  const cardClass =
    "person-card group border-2 border-white/10 bg-[var(--panel)] p-2 transition-all duration-150 hover:-translate-x-0.5 hover:-translate-y-0.5 hover:border-[var(--accent)] hover:shadow-[6px_6px_0px_0px_var(--accent)]";
  const content = (
    <>
      <Artwork
        className="border-0"
        src={person.photo_url}
        alt={person.name}
      />
      <p className="mt-2 line-clamp-2 font-black uppercase tracking-tight text-[var(--text)] text-sm">
        {person.name}
      </p>
      <small className="truncate font-mono text-[10px] uppercase tracking-widest text-[var(--subtle)]">
        {person.pivot?.character || person.character}
      </small>
    </>
  );
  return person.id ? (
    <Link className={cardClass} href={"/persons/" + person.id}>
      {content}
    </Link>
  ) : (
    <div className={cardClass}>{content}</div>
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
    <section className="relative mt-8 border-2 border-white/10 bg-[var(--panel)] p-6 shadow-[8px_8px_0px_0px_var(--accent)] sm:p-8">
      {/* Solid accent rule — ticket stub edge */}
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-1 bg-[var(--accent)]"
        aria-hidden="true"
      />
      <span className="inline-block border-2 border-[var(--accent)] bg-[var(--accent)] px-3 py-1 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)]">
        {entry ? "Твоя запись" : "Добавить в мой список"}
      </span>

      {statuses.isPending ? (
        <Loading />
      ) : statuses.error ? (
        <ErrorState error={statuses.error} />
      ) : (
        <form onSubmit={submit} className="form-stack mt-6">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Field label="Статус просмотра">
              <Select
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
              </Select>
            </Field>
            <Field label="Твоя оценка">
              <Select name="rating" defaultValue={entry?.rating || ""}>
                <option value="">Без оценки</option>
                {Array.from({ length: 10 }, (_, index) => (
                  <option key={index} value={index + 1}>
                    {index + 1} / 10
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Дата просмотра">
              <Input
                type="date"
                name="date"
                defaultValue={entry?.date?.slice(0, 10) || ""}
                className="[&::-webkit-calendar-picker-indicator]:cursor-pointer [&::-webkit-calendar-picker-indicator]:opacity-70"
              />
            </Field>
          </div>
          <Field label="Заметка для себя">
            <Textarea
              name="note"
              defaultValue={entry?.note || ""}
              maxLength={5000}
              placeholder="Что запомнилось?"
            />
          </Field>
          <div className="form-actions">
            <Button
              variant="primary"
              disabled={busy}
              className="w-full sm:w-auto sm:min-w-52"
            >
              {busy ? "Сохраняем…" : "Сохранить запись"}
            </Button>
            {entry && (
              <Link
                href="/entries"
                className="group inline-flex items-center gap-2 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--muted)] hover:text-[var(--accent)]"
              >
                Перейти к моему списку
                <ArrowRightIcon className="ui-icon" aria-hidden="true" />
              </Link>
            )}
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
            <Button
              variant="secondary"
              disabled={busy}
              key={list.id}
              className="h-auto w-full justify-between py-3 text-left"
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
              <span className="truncate">{list.name}</span>
              <small className="shrink-0 font-mono text-[10px] uppercase tracking-widest">
                {list.media_count} записей
              </small>
            </Button>
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