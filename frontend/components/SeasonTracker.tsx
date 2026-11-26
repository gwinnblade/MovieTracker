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
      <h2>Сезоны и серии</h2>
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
          className="mb-6 grid items-end gap-4 rounded-2xl border border-white/5 bg-[#151921]/80 p-5 shadow-[0_0_30px_rgba(229,169,61,0.04)] backdrop-blur-md sm:grid-cols-[8rem_minmax(0,1fr)_auto] sm:p-6"
          onSubmit={(event: FormEvent<HTMLFormElement>) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            const nextStatus = String(form.get("status"));
            void saveProgress(
              Number(form.get("watched")),
              nextStatus === status && ["planned", "watching", "completed"].includes(status) ? undefined : nextStatus,
            );
          }}
        >
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
            className="mt-4 h-2 w-full overflow-hidden rounded-full bg-white/[0.04] sm:col-span-3"
            role="progressbar"
            aria-label="Прогресс сезона"
            aria-valuenow={Math.min(watched, count)}
            aria-valuemin={0}
            aria-valuemax={count}
          >
            <span
              className="block h-full rounded-full bg-gradient-to-r from-gold/60 to-gold shadow-[0_0_8px_rgba(229,169,61,0.4)] transition-[width] duration-300"
              style={{
                width: `${count ? Math.min(100, (watched / count) * 100) : 0}%`,
              }}
            />
          </div>
        </form>
      ) : (
        <div className="rounded-xl border border-gold/20 bg-gold/5 p-4 text-sm text-zinc-300">
          <Link
            href="/login"
            className="font-medium text-gold hover:underline"
          >
            Войди
          </Link>
          , чтобы отмечать серии и сохранять заметки.
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
    <article className="mb-3 rounded-2xl border border-white/5 bg-[#151921] p-5 transition-all duration-300 hover:border-gold/15 hover:shadow-[0_0_20px_rgba(229,169,61,0.06)]">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h3 className="text-base! font-bold tracking-tight text-white">
            <span className="mr-2 inline-flex size-7 items-center justify-center rounded-lg border border-gold/20 bg-gold/10 align-middle text-xs font-bold text-gold tabular-nums">
              {episode.number}
            </span>
            {episode.title}
          </h3>
          <p className="mt-1.5! ml-9! flex flex-wrap items-center gap-2 text-xs text-zinc-500">
            {episode.air_date && <span>{episode.air_date}</span>}
            {episode.duration && <span>· {episode.duration} мин.</span>}
            {!!rating && (
              <span className="inline-flex items-center gap-1 rounded-full border border-gold/25 bg-gold/10 px-2 py-0.5 font-semibold text-gold tabular-nums">
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
                ? "shrink-0 border-emerald-500/30! text-emerald-400! enabled:hover:border-emerald-500/50! enabled:hover:bg-emerald-500/10! enabled:hover:text-emerald-300!"
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
        <p className="mt-3! ml-9! text-sm leading-relaxed text-zinc-400">
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
                className="shrink-0 text-red-400/70! hover:text-red-400!"
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