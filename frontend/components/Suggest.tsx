"use client";

import {
  MagnifyingGlassIcon,
  CheckIcon,
  FilmIcon,
  XMarkIcon,
  ArrowRightIcon,
} from "@heroicons/react/24/outline";
import Link from "next/link";
import { useSearchParams, useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { api, errorMessage } from "@/lib/api";
import type { Media } from "@/lib/types";
import { RequireAuth } from "./Auth";
import {
  Artwork,
  Button,
  ErrorState,
  Field,
  Input,
  Loading,
  PageHeading,
  Select,
  Textarea,
} from "./UI";

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
        eyebrow="[ ПОПОЛНИМ КАТАЛОГ ВМЕСТЕ ]"
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
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_340px] lg:items-start">
      <div className="relative border-2 border-white/10 bg-[var(--panel)] p-6 shadow-[8px_8px_0px_0px_var(--accent)] sm:p-8">
        {/* Solid accent rule — ticket stub edge */}
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-1 bg-[var(--accent)]"
          aria-hidden="true"
        />

        {!editId && (
          <section className="form-stack">
            <h2 className="flex items-center gap-3 border-b-2 border-white/10 pb-4 text-xl font-black uppercase tracking-tight text-[var(--text)]">
              <span className="inline-block border-2 border-[var(--accent)] bg-[var(--accent)] px-2 py-0.5 font-mono text-[10px] font-black uppercase tracking-widest text-[var(--bg)]">
                01
              </span>
              Найти в TMDB
            </h2>
            <div className="form-row">
              <Field label="Название">
                <div className="relative">
                  <MagnifyingGlassIcon
                    className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-[var(--subtle)]"
                    aria-hidden="true"
                  />
                  <Input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Например, Интерстеллар"
                    maxLength={150}
                    className="pl-10"
                  />
                </div>
              </Field>
              <Field label="Искать">
                <Select
                  value={type}
                  onChange={(e) => setType(e.target.value)}
                >
                  <option value="all">Фильмы и сериалы</option>
                  <option value="movie">Фильмы</option>
                  <option value="tv">Сериалы</option>
                </Select>
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
                  <div className="max-h-[420px] space-y-2 overflow-y-auto pr-1 [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-thumb]:bg-white/10 hover:[&::-webkit-scrollbar-thumb]:bg-[var(--accent)] [scrollbar-width:thin]">
                    {search.data?.data.slice(0, 8).map((media) => (
                      <button
                        type="button"
                        disabled={selecting}
                        key={`${media.tmdb_type}-${media.tmdb_id}`}
                        onClick={() => void select(media)}
                        className="group flex w-full items-center gap-3 border-2 border-white/10 bg-[var(--bg)] p-2.5 text-left transition-[transform,box-shadow,border-color] duration-150 ease-out hover:-translate-x-0.5 hover:-translate-y-0.5 hover:border-[var(--accent)] hover:shadow-[4px_4px_0px_0px_var(--accent)] focus-visible:outline-2 focus-visible:outline-[var(--accent)] focus-visible:outline-offset-2"
                      >
                        <Artwork
                          src={media.poster_url}
                          alt={media.title_ru}
                          className="w-12 shrink-0 border-2 border-white/20"
                        />
                        <div className="min-w-0 flex-1">
                          <p className="truncate font-black uppercase tracking-tight text-[var(--text)] transition-colors duration-150 group-hover:text-[var(--accent)]">
                            {media.title_ru}
                          </p>
                          <p className="mt-0.5 font-mono text-[10px] uppercase tracking-widest text-[var(--subtle)]">
                            {media.release_date?.slice(0, 4)} ·{" "}
                            {media.tmdb_type === "tv" ? "Сериал" : "Фильм"}
                          </p>
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </>
            )}
            {selected && (
              <div className="mt-2 flex items-center justify-between gap-3 border-2 border-[var(--bg)] bg-[var(--green)] px-4 py-3">
                <div className="flex items-center gap-2 text-sm font-black uppercase tracking-wider text-[var(--bg)]">
                  <CheckIcon className="size-4 shrink-0" aria-hidden="true" />
                  <span>
                    TMDB:{" "}
                    <span className="font-black">
                      {selected.title_ru}
                    </span>
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setSelected(undefined)}
                  className="inline-flex shrink-0 items-center gap-1 font-mono text-[10px] font-black uppercase tracking-widest text-[var(--bg)] transition-colors duration-150 hover:text-[var(--bg)]/70"
                >
                  <XMarkIcon className="size-3.5" aria-hidden="true" />
                  Вручную
                </button>
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
          <h2 className="flex items-center gap-3 border-b-2 border-white/10 pb-4 text-xl font-black uppercase tracking-tight text-[var(--text)]">
            <span className="inline-block border-2 border-[var(--accent)] bg-[var(--accent)] px-2 py-0.5 font-mono text-[10px] font-black uppercase tracking-widest text-[var(--bg)]">
              02
            </span>
            Карточка для каталога
          </h2>
          <Field label="Русское название">
            <Input
              name="title_ru"
              required
              maxLength={255}
              defaultValue={selected?.title_ru || ""}
            />
          </Field>
          <Field label="Оригинальное название">
            <Input
              name="title_en"
              maxLength={255}
              defaultValue={selected?.title_en || ""}
            />
          </Field>
          <div className="form-row">
            <Field label="Тип">
              <Select
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
              </Select>
            </Field>
            <Field label="Год выхода">
              <Input
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
            <Textarea
              name="description_ru"
              maxLength={10000}
              defaultValue={selected?.description_ru || ""}
            />
          </Field>

          <div className="field">
            <span>Постер</span>
            <label className="group flex cursor-pointer flex-col items-center justify-center gap-2 border-2 border-dashed border-white/20 bg-[var(--bg)] px-6 py-8 text-center transition-[border-color,box-shadow] duration-150 ease-out hover:border-[var(--accent)] hover:shadow-[6px_6px_0px_0px_var(--accent)] focus-within:border-[var(--accent)] focus-within:shadow-[6px_6px_0px_0px_var(--accent)]">
              <FilmIcon
                className="size-8 text-[var(--subtle)] transition-colors duration-150 group-hover:text-[var(--accent)]"
                aria-hidden="true"
              />
              <span className="text-sm text-[var(--muted)]">
                <span className="font-black uppercase tracking-wider text-[var(--text)]">Нажми</span> или
                перетащи файл сюда
              </span>
              <span className="font-mono text-[10px] uppercase tracking-widest text-[var(--subtle)]">
                JPEG, PNG или WebP, до 5 МБ
              </span>
              <input
                name="poster"
                type="file"
                accept="image/jpeg,image/png,image/webp"
                className="ui-control sr-only"
              />
            </label>
            <small>
              {selected?.poster_url
                ? "Постер TMDB уже выбран. Можно загрузить свой, до 5 МБ."
                : "JPEG, PNG или WebP, до 5 МБ"}
            </small>
          </div>

          <div className="space-y-2">
            <span className="font-mono text-[11px] font-black uppercase tracking-widest text-[var(--muted)]">Жанры</span>
            <div className="flex flex-wrap gap-2">
              {genres.data?.map((genre) => (
                <label
                  key={`${genre.id}-${selected?.tmdb_id}`}
                  className="cursor-pointer select-none"
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
                    className="peer ui-control sr-only"
                  />
                  <span className="inline-flex items-center border-2 border-white/20 bg-white/5 px-3 py-1.5 font-mono text-[10px] font-black uppercase tracking-widest text-[var(--muted)] transition-[background-color,border-color,color] duration-150 ease-out hover:border-white/40 hover:text-[var(--text)] peer-checked:border-[var(--bg)] peer-checked:bg-[var(--accent)] peer-checked:text-[var(--bg)] peer-focus-visible:outline-2 peer-focus-visible:outline-[var(--accent)] peer-focus-visible:outline-offset-2">
                    {genre.name_ru}
                  </span>
                </label>
              ))}
            </div>
          </div>

          <Button
            type="submit"
            variant="primary"
            disabled={busy || selecting || types.isPending}
            className="w-full"
          >
            {busy ? "Отправляем…" : "Отправить на модерацию"}
          </Button>
        </form>
      </div>

      <aside className="sticky top-24 border-2 border-white/10 bg-[var(--panel)] p-6 shadow-[6px_6px_0px_0px_var(--accent)]">
        {/* Solid accent rule — ticket stub edge */}
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-1 bg-[var(--accent)]"
          aria-hidden="true"
        />
        <span className="inline-block border-2 border-[var(--accent)] bg-[var(--accent)] px-3 py-1 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)]">
          [ После проверки ]
        </span>
        {selected ? (
          <>
            <Artwork
              src={selected.poster_url || selected.poster_key}
              alt={selected.title_ru}
              className="mx-auto mt-5 w-full max-w-[220px] border-2 border-white/20 shadow-[10px_10px_0px_0px_var(--accent)]"
            />
            <h3 className="mt-4 text-lg font-black uppercase leading-tight tracking-tight text-[var(--text)]">
              {selected.title_ru}
            </h3>
            {selected.director && (
              <p className="mt-2 font-mono text-[10px] uppercase tracking-widest text-[var(--subtle)]">
                <span className="text-[var(--muted)]">Режиссёр:</span>{" "}
                {selected.director.name}
              </p>
            )}
            {!!selected.cast?.length && (
              <p className="mt-2 font-mono text-[10px] uppercase tracking-widest text-[var(--subtle)]">
                <span className="text-[var(--muted)]">В ролях:</span>{" "}
                {selected.cast
                  .slice(0, 5)
                  .map((person) => person.name)
                  .join(", ")}
              </p>
            )}
          </>
        ) : (
          <div className="mt-5 flex flex-col items-center gap-3 border-2 border-dashed border-white/20 bg-[var(--bg)] px-4 py-8 text-center">
            <FilmIcon className="size-8 text-[var(--subtle)]" aria-hidden="true" />
            <p className="font-mono text-[10px] uppercase tracking-widest leading-relaxed text-[var(--subtle)]">
              Выбери фильм в TMDB или заполни карточку вручную — здесь появится
              превью.
            </p>
          </div>
        )}
        <div className="mt-5 space-y-3 border-t-2 border-white/10 pt-5 font-mono text-[10px] uppercase tracking-widest leading-relaxed text-[var(--subtle)]">
          <p>
            Заявка сначала появится в разделе «Мои заявки». После одобрения
            карточка попадёт в общий каталог.
          </p>
          <p className="mt-3">
            Статус и причина отклонения всегда доступны автору.
          </p>
        </div>
        <Link
          href="/moderation"
          className="group mt-5 inline-flex items-center gap-2 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--accent)] transition-colors duration-150 hover:text-[var(--accent-hover)]"
        >
          Посмотреть заявки{" "}
          <ArrowRightIcon
            className="size-4 transition-transform duration-150 group-hover:translate-x-1"
            aria-hidden="true"
          />
        </Link>
      </aside>
    </div>
  );
}