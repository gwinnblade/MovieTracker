"use client";

import Link from "next/link";
import { useSearchParams, useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { api, errorMessage } from "@/lib/api";
import type { Media } from "@/lib/types";
import { RequireAuth } from "./Auth";
import { Artwork, ErrorState, Field, Loading, PageHeading } from "./UI";

function useDebounced(value: string) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), 350);
    return () => clearTimeout(timer);
  }, [value]);
  return debounced;
}

export default function Suggest() {
  const params = useSearchParams();
  const mediaId = Number(params.get("media_id")) || undefined;
  const tmdbId = Number(params.get("tmdb_id")) || undefined;
  const type = params.get("type") === "tv" ? "tv" : "movie";
  const initial = useQuery({
    queryKey: ["suggest-initial", mediaId, tmdbId, type],
    queryFn: () =>
      mediaId ? api.media(mediaId) : api.tmdbDetails(type, tmdbId!),
    enabled: !!mediaId || !!tmdbId,
  });
  return (
    <RequireAuth>
      <PageHeading
        eyebrow="ПОПОЛНИМ КАТАЛОГ ВМЕСТЕ"
        title={mediaId ? "Предложить исправление" : "Предложить фильм"}
        description="Выбери фильм или сериал в TMDB либо заполни карточку самостоятельно. Модератор проверит заявку перед публикацией."
      />
      {(mediaId || tmdbId) && initial.isPending ? (
        <Loading />
      ) : initial.error ? (
        <ErrorState error={initial.error} retry={() => initial.refetch()} />
      ) : (
        <SuggestEditor
          key={`${mediaId}-${tmdbId}-${type}`}
          initial={initial.data}
          editId={mediaId}
        />
      )}
    </RequireAuth>
  );
}

function SuggestEditor({
  initial,
  editId,
}: {
  initial?: Media;
  editId?: number;
}) {
  const router = useRouter();
  const cache = useQueryClient();
  const [selected, setSelected] = useState<Media | undefined>(initial);
  const [query, setQuery] = useState("");
  const [type, setType] = useState("all");
  const [busy, setBusy] = useState(false);
  const [selecting, setSelecting] = useState(false);
  const debounced = useDebounced(query);
  const types = useQuery({
    queryKey: ["types"],
    queryFn: () => api.references("types"),
  });
  const genres = useQuery({
    queryKey: ["genres"],
    queryFn: () => api.references("genres"),
  });
  const search = useQuery({
    queryKey: ["suggest-search", debounced, type],
    queryFn: () => api.search({ query: debounced, type }),
    enabled: debounced.trim().length >= 2 && !editId,
  });
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const poster = form.get("poster");
    if (poster instanceof File && !poster.size) form.delete("poster");
    if (selected?.tmdb_id && selected.tmdb_type) {
      form.set("tmdb_id", String(selected.tmdb_id));
      form.set("tmdb_type", selected.tmdb_type);
    }
    if (editId) form.set("media_id", String(editId));
    if (!form.getAll("genre_ids[]").length) form.set("clear_genres", "1");
    setBusy(true);
    try {
      await api.suggest(form);
      await cache.invalidateQueries({ queryKey: ["requests"] });
      toast.success("Заявка отправлена на модерацию");
      router.push("/moderation");
    } catch (error) {
      toast.error(errorMessage(error));
    } finally {
      setBusy(false);
    }
  };
  const select = async (media: Media) => {
    setSelecting(true);
    try {
      setSelected(await api.tmdbDetails(media.tmdb_type!, media.tmdb_id!));
      setQuery("");
    } catch (error) {
      toast.error(errorMessage(error));
    } finally {
      setSelecting(false);
    }
  };
  return (
    <div className="suggest-layout">
      <div className="suggest-form panel">
        {!editId && (
          <section className="form-stack">
            <h2>Найти в TMDB</h2>
            <div className="form-row">
              <Field label="Название">
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Например, Интерстеллар"
                  maxLength={150}
                />
              </Field>
              <Field label="Искать">
                <select value={type} onChange={(e) => setType(e.target.value)}>
                  <option value="all">Фильмы и сериалы</option>
                  <option value="movie">Фильмы</option>
                  <option value="tv">Сериалы</option>
                </select>
              </Field>
            </div>
            {selecting && <Loading text="Заполняем карточку…" />}
            {debounced.length >= 2 && query.length >= 2 && (
              <>
                {search.isPending ? (
                  <Loading />
                ) : search.error ? (
                  <ErrorState error={search.error} />
                ) : (
                  <div className="suggest-search-results">
                    {search.data?.data.slice(0, 8).map((media) => (
                      <button
                        type="button"
                        className="suggest-result"
                        disabled={selecting}
                        key={`${media.tmdb_type}-${media.tmdb_id}`}
                        onClick={() => void select(media)}
                      >
                        <Artwork src={media.poster_url} alt={media.title_ru} />
                        <div>
                          {media.title_ru}
                          <small>
                            {media.release_date?.slice(0, 4)} ·{" "}
                            {media.tmdb_type === "tv" ? "Сериал" : "Фильм"}
                          </small>
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </>
            )}
            {selected && (
              <div className="notice">
                <span>Данные TMDB выбраны: {selected.title_ru}</span>
                <div className="form-actions">
                  <button
                    className="text-button"
                    onClick={() => setSelected(undefined)}
                  >
                    Заполнить вручную
                  </button>
                </div>
              </div>
            )}
          </section>
        )}
        <form
          className="form-stack section"
          onSubmit={submit}
          key={`${selected?.id}-${selected?.tmdb_type}-${selected?.tmdb_id}`}
        >
          {types.error && <ErrorState error={types.error} />}
          {genres.error && <ErrorState error={genres.error} />}
          <h2>Карточка для каталога</h2>
          <Field label="Русское название">
            <input
              name="title_ru"
              required
              maxLength={255}
              defaultValue={selected?.title_ru || ""}
            />
          </Field>
          <Field label="Оригинальное название">
            <input
              name="title_en"
              maxLength={255}
              defaultValue={selected?.title_en || ""}
            />
          </Field>
          <div className="form-row">
            <Field label="Тип">
              <select
                name="type_id"
                key={`${selected?.type_id}-${types.data?.length}-${selected?.tmdb_type}`}
                defaultValue={
                  selected?.type_id ||
                  types.data?.find(
                    (item) =>
                      item.code ===
                      (selected?.tmdb_type === "tv" ? "series" : "movie"),
                  )?.id ||
                  ""
                }
                required
              >
                <option value="" disabled>
                  Выбери тип
                </option>
                {types.data?.map((item) => (
                  <option value={item.id} key={item.id}>
                    {item.name_ru}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Год выхода">
              <input
                name="release_year"
                type="number"
                min={1800}
                max={2200}
                defaultValue={selected?.release_date?.slice(0, 4) || ""}
                placeholder="Например, 2014"
              />
            </Field>
          </div>
          <Field label="Описание">
            <textarea
              name="description_ru"
              maxLength={10000}
              defaultValue={selected?.description_ru || ""}
            />
          </Field>
          <Field
            label="Постер"
            hint={
              selected?.poster_url
                ? "Постер TMDB уже выбран. Можно загрузить свой, до 5 МБ."
                : "JPEG, PNG или WebP, до 5 МБ"
            }
          >
            <input
              name="poster"
              type="file"
              accept="image/jpeg,image/png,image/webp"
            />
          </Field>
          <div className="field">
            <span>Жанры</span>
            <div className="genre-select">
              {genres.data?.map((genre) => (
                <label
                  className="check-label"
                  key={`${genre.id}-${selected?.tmdb_id}`}
                >
                  <input
                    type="checkbox"
                    name="genre_ids[]"
                    value={genre.id}
                    defaultChecked={
                      selected?.genres?.some(
                        (item) =>
                          item.id === genre.id ||
                          item.name_ru.toLocaleLowerCase("ru") ===
                            genre.name_ru.toLocaleLowerCase("ru"),
                      ) || false
                    }
                  />
                  {genre.name_ru}
                </label>
              ))}
            </div>
          </div>
          <button
            className="button"
            disabled={busy || selecting || types.isPending}
          >
            {busy ? "Отправляем…" : "Отправить на модерацию"}
          </button>
        </form>
      </div>
      <aside className="suggest-preview panel">
        <span className="eyebrow">ПОСЛЕ ПРОВЕРКИ</span>
        {selected && (
          <>
            <Artwork
              src={selected.poster_url || selected.poster_key}
              alt={selected.title_ru}
            />
            <h3>{selected.title_ru}</h3>
            {selected.director && <p>Режиссёр: {selected.director.name}</p>}
            {!!selected.cast?.length && (
              <p>
                В ролях:{" "}
                {selected.cast
                  .slice(0, 5)
                  .map((person) => person.name)
                  .join(", ")}
              </p>
            )}
          </>
        )}
        <p>
          Заявка сначала появится в разделе «Мои заявки». После одобрения
          карточка попадёт в общий каталог.
        </p>
        <p>Статус и причина отклонения всегда доступны автору.</p>
        <Link href="/moderation">Посмотреть заявки →</Link>
      </aside>
    </div>
  );
}
