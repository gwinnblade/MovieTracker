"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { api, errorMessage } from "@/lib/api";
import type { Episode, Media, Tracking } from "@/lib/types";
import { Empty, ErrorState, Field, Loading } from "./UI";

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
          <div className="season-controls">
            <Field label="Выбери сезон">
              <select
                value={selected}
                onChange={(e) => setSelected(Number(e.target.value))}
              >
                {seasons.map((season) => (
                  <option key={season.season} value={season.season}>
                    {season.name} · {season.episode_count} серий
                  </option>
                ))}
              </select>
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
          className="season-progress panel"
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
            <input
              name="watched"
              type="number"
              min={0}
              max={count}
              defaultValue={Math.min(watched, count)}
              required
            />
          </Field>
          <Field label="Статус сезона">
            <select name="status" defaultValue={status}>
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
            </select>
          </Field>
          <button className="button" disabled={busy}>
            Сохранить прогресс
          </button>
          <div
            className="progress-bar"
            role="progressbar"
            aria-label="Прогресс сезона"
            aria-valuenow={Math.min(watched, count)}
            aria-valuemin={0}
            aria-valuemax={count}
          >
            <span
              style={{
                width: `${count ? Math.min(100, (watched / count) * 100) : 0}%`,
              }}
            />
          </div>
        </form>
      ) : (
        <p className="notice">
          <Link href="/login">Войди</Link>, чтобы отмечать серии и сохранять
          заметки.
        </p>
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
    <article className="episode">
      <div className="episode-heading">
        <div>
          <h3>
            {episode.number}. {episode.title}
          </h3>
          {episode.air_date && (
            <small>
              {episode.air_date}
              {episode.duration ? ` · ${episode.duration} мин.` : ""}
            </small>
          )}
        </div>
        {userId && (
          <button
            type="button"
            className={"button small " + (watched ? "secondary" : "")}
            disabled={busy}
            onClick={() => void onWatch()}
          >
            {watched ? "✓ Просмотрено" : "Отметить просмотр"}
          </button>
        )}
      </div>
      {episode.description_ru && <p>{episode.description_ru}</p>}
      {userId && (
        <>
          <div className="episode-note">
            <Field label={`Заметка к серии ${episode.number}`}>
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                maxLength={5000}
                placeholder="Любимый момент, мысль или цитата…"
              />
            </Field>
            <button
              className="button secondary small"
              disabled={saving}
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
            </button>
            {note && (
              <button
                className="text-button"
                disabled={saving}
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
                Удалить
              </button>
            )}
          </div>
          <div className="season-controls">
            <Field label={`Оценка серии ${episode.number}`}>
              <select
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
              </select>
            </Field>
          </div>
        </>
      )}
    </article>
  );
}
