"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import toast from "react-hot-toast";
import {
  CheckCircleIcon,
  CheckIcon,
  ClockIcon,
  StarIcon,
  TrashIcon,
} from "@heroicons/react/24/outline";
import { api, errorMessage } from "@/lib/api";
import type { Episode, Media, Tracking } from "@/lib/types";
import {
  Button,
  Empty,
  ErrorState,
  Field,
  Input,
  Loading,
  Select,
  Textarea,
} from "./UI";

const stampClasses =
  "inline-block border-2 border-[var(--accent)] bg-[var(--accent)] px-3 py-1 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)]";

const barTrackClasses =
  "h-3 w-full overflow-hidden border-2 border-white/15 bg-[var(--bg)] sm:col-span-3";

const barFillClasses =
  "block h-full bg-[var(--accent)] transition-[width] duration-150 ease-out";

export default function SeasonTracker({
  media,
  tracking,
  userId,
  ensureLocal,
  onSaved,
}: {
  media: Media;
  tracking?: Tracking;
  userId?: number;
  ensureLocal: () => Promise<Media>;
  onSaved: () => Promise<void>;
}) {
  const seasons = media.seasons?.length
    ? media.seasons
    : Array.from(
        new Set(media.episodes?.map((episode) => episode.season) || []),
      ).map((season) => ({
        season,
        name: "Сезон " + season,
        episode_count:
          media.episodes?.filter((e) => e.season === season).length || 0,
      }));
  const [selected, setSelected] = useState(
    seasons.find((season) => season.season === 1)?.season ??
      seasons[0]?.season ??
      1,
  );
  const episodes = useQuery({
    queryKey: ["season", media.id, media.tmdb_id, selected],
    queryFn: () =>
      media.id
        ? api.season(media.id, selected)
        : api.tmdbSeason(media.tmdb_id!, selected),
    enabled: !!seasons.length,
  });
  const progress = tracking?.seasons.find((item) => item.season === selected);
  return (
    <section className="section">
      <div className="mb-6 flex items-center gap-3 border-b-2 border-white/10 pb-4">
        <span className={stampClasses}>Сезоны и серии</span>
      </div>
      {!seasons.length ? (
        <Empty title="Список серий пока не заполнен" />
      ) : (
        <>
          <div className="mb-6 max-w-xs">
            <Field label="Выбери сезон">
              <Select
                value={selected}
                onChange={(e) => setSelected(Number(e.target.value))}
              >
                {seasons.map((season) => (
                  <option key={season.season} value={season.season}>
                    {season.name} · {season.episode_count} серий
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          {episodes.isPending ? (
            <Loading text="Загрузка серий…" />
          ) : episodes.error ? (
            <ErrorState
              error={episodes.error}
              retry={() => episodes.refetch()}
            />
          ) : (
            <SeasonPanel
              key={`${selected}-${progress?.watched}-${progress?.status}`}
              season={selected}
              episodes={episodes.data.episodes}
              watched={progress?.watched || 0}
              status={progress?.status || "planned"}
              tracking={tracking}
              userId={userId}
              ensureLocal={ensureLocal}
              onSaved={onSaved}
            />
          )}
        </>
      )}
    </section>
  );
}

function SeasonPanel({
  season,
  episodes,
  watched,
  status,
  tracking,
  userId,
  ensureLocal,
  onSaved,
}: {
  season: number;
  episodes: Episode[];
  watched: number;
  status: string;
  tracking?: Tracking;
  userId?: number;
  ensureLocal: () => Promise<Media>;
  onSaved: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const count = episodes.length;
  const statuses = useQuery({
    queryKey: ["statuses"],
    queryFn: () => api.references("statuses"),
    enabled: !!userId,
  });
  const saveProgress = async (number: number, nextStatus?: string) => {
    setBusy(true);
    try {
      const media = await ensureLocal();
      await api.progress(media.id!, season, number, nextStatus);
      await onSaved();
      toast.success("Прогресс сохранён");
    } catch (error) {
      toast.error(errorMessage(error));
    } finally {
      setBusy(false);
    }
  };
  const saveRating = async (episode: Episode, rating: number | null) => {
    const media = await ensureLocal();
    const stored = await api.season(media.id!, season);
    const record = stored.episodes.find((e) => e.number === episode.number);
    if (!record?.id) throw new Error("Не удалось найти серию.");
    const statusId =
      tracking?.entry?.status_id ||
      statuses.data?.find((status) => status.code === "watching")?.id;
    if (!statusId) throw new Error("Статусы ещё загружаются.");
    await api.saveEntry({
      media_id: media.id!,
      status_id: statusId,
      episodes: [
        { episode_id: record.id, watched: episode.number <= watched, rating },
      ],
    });
    await onSaved();
  };
  return (
    <>
      {userId ? (
        <form
          className="relative mb-6 grid items-end gap-4 border-2 border-white/10 bg-[var(--panel)] p-5 shadow-[8px_8px_0px_0px_var(--accent)] sm:grid-cols-[8rem_minmax(0,1fr)_auto] sm:p-6"
          onSubmit={(event: FormEvent<HTMLFormElement>) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            const nextStatus = String(form.get("status"));
            void saveProgress(
              Number(form.get("watched")),
              nextStatus === status &&
                ["planned", "watching", "completed"].includes(status)
                ? undefined
                : nextStatus,
            );
          }}
        >
          {/* Solid accent rule — ticket stub edge */}
          <div
            className="pointer-events-none absolute inset-x-0 top-0 h-1 bg-[var(--accent)]"
            aria-hidden="true"
          />
          <Field label={`Просмотрено из ${count}`}>
            <Input
              name="watched"
              type="number"
              min={0}
              max={count}
              defaultValue={Math.min(watched, count)}
              required
            />
          </Field>
          <Field label="Статус сезона">
            <Select name="status" defaultValue={status}>
              {[
                ["planned", "Запланировано"],
                ["watching", "Смотрю"],
                ["completed", "Просмотрено"],
                ["dropped", "Заброшено"],
                ["paused", "Отложено"],
                ["untracked", "Без статуса"],
              ].map(([value, title]) => (
                <option value={value} key={value}>
                  {title}
                </option>
              ))}
            </Select>
          </Field>
          <Button
            type="submit"
            variant="primary"
            disabled={busy}
            className="w-full sm:w-auto"
          >
            <CheckIcon className="size-4" aria-hidden="true" /> Сохранить
            прогресс
          </Button>
          <div
            className={barTrackClasses}
            role="progressbar"
            aria-label="Прогресс сезона"
            aria-valuenow={Math.min(watched, count)}
            aria-valuemin={0}
            aria-valuemax={count}
          >
            <span
              className={barFillClasses}
              style={{
                width: `${count ? Math.min(100, (watched / count) * 100) : 0}%`,
              }}
            />
          </div>
        </form>
      ) : (
        <div className="border-2 border-[var(--accent)] bg-[var(--accent)]/10 p-4 text-sm text-[var(--text)] shadow-[4px_4px_0px_0px_var(--accent)]">
          <Link
            href="/login"
            className="font-black uppercase tracking-wider text-[var(--accent)] hover:underline"
          >
            Войди
          </Link>{" "}
          <span className="text-[var(--muted)]">
            , чтобы отмечать серии и сохранять заметки.
          </span>
        </div>
      )}
      {episodes.map((episode) => (
        <EpisodeRow
          key={`${season}-${episode.number}-${tracking?.episode_notes.find((note) => note.season === season && note.episode === episode.number)?.note || ""}`}
          episode={episode}
          watched={episode.number <= watched}
          userId={userId}
          busy={busy}
          note={
            tracking?.episode_notes.find(
              (note) =>
                note.season === season && note.episode === episode.number,
            )?.note || ""
          }
          rating={
            tracking?.entry?.episode_entries?.find(
              (entry) =>
                entry.episode?.season === season &&
                entry.episode?.number === episode.number,
            )?.rating ?? null
          }
          onWatch={() =>
            saveProgress(
              episode.number <= watched ? episode.number - 1 : episode.number,
            )
          }
          onNote={async (note) => {
            const media = await ensureLocal();
            await api.episodeNote(media.id!, season, episode.number, note);
            await onSaved();
          }}
          onRating={(rating) => saveRating(episode, rating)}
        />
      ))}
    </>
  );
}

function EpisodeRow({
  episode,
  watched,
  userId,
  busy,
  note,
  rating,
  onWatch,
  onNote,
  onRating,
}: {
  episode: Episode;
  watched: boolean;
  userId?: number;
  busy: boolean;
  note: string;
  rating: number | null;
  onWatch: () => Promise<void>;
  onNote: (note: string) => Promise<void>;
  onRating: (rating: number | null) => Promise<void>;
}) {
  const [text, setText] = useState(note);
  const [saving, setSaving] = useState(false);
  return (
    <article className="mb-3 border-2 border-white/10 bg-[var(--panel)] p-5 shadow-[6px_6px_0px_0px_rgba(255,255,255,0.05)] transition-[transform,box-shadow,border-color] duration-150 ease-out hover:-translate-x-0.5 hover:-translate-y-0.5 hover:border-[var(--accent)] hover:shadow-[8px_8px_0px_0px_var(--accent)]">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h3 className="text-base font-black uppercase tracking-tight text-[var(--text)]">
            <span className="mr-2 inline-flex size-7 items-center justify-center border-2 border-[var(--bg)] bg-[var(--accent)] align-middle font-mono text-xs font-black uppercase text-[var(--bg)] shadow-[2px_2px_0px_0px_var(--text)] tabular-nums">
              {episode.number}
            </span>
            {episode.title}
          </h3>
          <p className="mt-1.5 ml-9 flex flex-wrap items-center gap-2 font-mono text-[11px] uppercase tracking-widest text-[var(--subtle)]">
            {episode.air_date && <span>{episode.air_date}</span>}
            {episode.duration && <span>· {episode.duration} мин.</span>}
            {!!rating && (
              <span className="inline-flex items-center gap-1 border-2 border-[var(--bg)] bg-[var(--accent)] px-2 py-0.5 font-mono text-[10px] font-black uppercase tracking-widest text-[var(--bg)] shadow-[2px_2px_0px_0px_var(--text)] tabular-nums">
                <StarIcon className="size-3" aria-hidden="true" />
                {rating}/10
              </span>
            )}
          </p>
        </div>
        {userId && (
          <Button
            type="button"
            variant={watched ? "secondary" : "primary"}
            disabled={busy}
            onClick={() => void onWatch()}
            className={
              watched
                ? "shrink-0 border-2 border-[var(--bg)] bg-[var(--green)]/10 text-[var(--green)] shadow-[3px_3px_0px_0px_var(--green)] enabled:hover:-translate-x-0.5 enabled:hover:-translate-y-0.5 enabled:hover:shadow-[4px_4px_0px_0px_var(--green)]"
                : "shrink-0"
            }
          >
            {watched ? (
              <CheckCircleIcon className="size-4" aria-hidden="true" />
            ) : (
              <ClockIcon className="size-4" aria-hidden="true" />
            )}
            {watched ? "Просмотрено" : "Отметить"}
          </Button>
        )}
      </div>
      {episode.description_ru && (
        <p className="mt-3 ml-9 text-sm leading-relaxed text-[var(--muted)]">
          {episode.description_ru}
        </p>
      )}
      {userId && (
        <>
          <div className="mt-4 ml-9 flex flex-col gap-2 sm:flex-row sm:items-end">
            <div className="min-w-0 flex-1">
              <Field label={`Заметка к серии ${episode.number}`}>
                <Textarea
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  maxLength={5000}
                  placeholder="Любимый момент, мысль или цитата…"
                  className="min-h-20!"
                />
              </Field>
            </div>
            <Button
              type="button"
              variant="secondary"
              disabled={saving}
              className="shrink-0"
              onClick={async () => {
                setSaving(true);
                try {
                  await onNote(text);
                  toast.success(
                    text.trim() ? "Заметка сохранена" : "Заметка удалена",
                  );
                } catch (error) {
                  toast.error(errorMessage(error));
                } finally {
                  setSaving(false);
                }
              }}
            >
              Сохранить заметку
            </Button>
            {note && (
              <Button
                type="button"
                variant="ghost"
                disabled={saving}
                className="shrink-0 border-2 border-transparent text-[var(--red)] hover:border-[var(--red)] hover:bg-[var(--red)]/10"
                onClick={async () => {
                  setSaving(true);
                  try {
                    await onNote("");
                    setText("");
                    toast.success("Заметка удалена");
                  } catch (error) {
                    toast.error(errorMessage(error));
                  } finally {
                    setSaving(false);
                  }
                }}
              >
                <TrashIcon className="size-4" aria-hidden="true" /> Удалить
              </Button>
            )}
          </div>
          <div className="mt-3 ml-9 max-w-xs">
            <Field label={`Оценка серии ${episode.number}`}>
              <Select
                value={rating || ""}
                disabled={saving}
                onChange={async (event) => {
                  const value = event.target.value;
                  setSaving(true);
                  try {
                    await onRating(value ? Number(value) : null);
                    toast.success("Оценка серии сохранена");
                  } catch (error) {
                    toast.error(errorMessage(error));
                  } finally {
                    setSaving(false);
                  }
                }}
              >
                <option value="">Без оценки</option>
                {Array.from({ length: 10 }, (_, index) => (
                  <option key={index} value={index + 1}>
                    {index + 1} / 10
                  </option>
                ))}
              </Select>
            </Field>
          </div>
        </>
      )}
    </article>
  );
}