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
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_340px] lg:items-start">
      <div className="rounded-2xl border border-white/5 bg-[#151921] p-6 sm:p-8">
        {!editId && (
          <section className="form-stack">
            <h2 className="flex items-center gap-2 text-xl! font-bold! tracking-tight! text-white">
              <MagnifyingGlassIcon
                className="size-5 text-gold"
                aria-hidden="true"
              />
              Найти в TMDB
            </h2>
            <div className="form-row">
              <Field label="Название">
                <div className="relative">
                  <MagnifyingGlassIcon
                    className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-zinc-500"
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
                  <div className="max-h-[420px] space-y-2 overflow-y-auto pr-1 [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-white/10 hover:[&::-webkit-scrollbar-thumb]:bg-gold/40 [scrollbar-width:thin]">
                    {search.data?.data.slice(0, 8).map((media) => (
                      <button
                        type="button"
                        disabled={selecting}
                        key={`${media.tmdb_type}-${media.tmdb_id}`}
                        onClick={() => void select(media)}
                        className="group flex w-full items-center gap-3 rounded-xl border border-white/5 bg-[#0B0E14] p-2.5 text-left transition-all duration-200 hover:border-gold/30 hover:bg-gold/[0.03] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold/40"
                      >
                        <Artwork
                          src={media.poster_url}
                          alt={media.title_ru}
                          className="w-12 shrink-0 rounded-md"
                        />
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm font-medium text-white transition-colors group-hover:text-gold">
                            {media.title_ru}
                          </p>
                          <p className="mt-0.5! text-xs text-zinc-500">
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
              <div className="mt-2 flex items-center justify-between gap-3 rounded-xl border border-emerald-500/20 bg-emerald-500/[0.05] px-4 py-3">
                <div className="flex items-center gap-2 text-sm text-emerald-300">
                  <CheckIcon className="size-4 shrink-0" aria-hidden="true" />
                  <span>
                    TMDB:{" "}
                    <span className="font-medium text-emerald-200">
                      {selected.title_ru}
                    </span>
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setSelected(undefined)}
                  className="inline-flex shrink-0 items-center gap-1 text-xs text-zinc-400 transition-colors hover:text-white"
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
          <h2 className="flex items-center gap-2 text-xl! font-bold! tracking-tight! text-white">
            <FilmIcon className="size-5 text-gold" aria-hidden="true" />
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
            <label className="group flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed border-white/10 bg-[#0B0E14] px-6 py-8 text-center transition-all duration-200 hover:border-gold/40 hover:bg-gold/[0.02] focus-within:border-gold/40 focus-within:ring-2 focus-within:ring-gold/20">
              <FilmIcon
                className="size-8 text-zinc-600 transition-colors group-hover:text-gold"
                aria-hidden="true"
              />
              <span className="text-sm text-zinc-400">
                <span className="font-medium text-white">Нажми</span> или
                перетащи файл сюда
              </span>
              <span className="text-xs text-zinc-600">
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
            <span className="text-sm font-medium text-zinc-300">Жанры</span>
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
                  <span className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs font-medium text-zinc-400 transition-all duration-200 hover:border-white/20 hover:text-white peer-checked:border-gold/40 peer-checked:bg-gold/10 peer-checked:text-gold peer-focus-visible:ring-2 peer-focus-visible:ring-gold/40">
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

      <aside className="sticky top-24 rounded-2xl border border-white/5 bg-gradient-to-br from-[#151921] to-[#0B0E14] p-6">
        <span className="eyebrow">ПОСЛЕ ПРОВЕРКИ</span>
        {selected ? (
          <>
            <Artwork
              src={selected.poster_url || selected.poster_key}
              alt={selected.title_ru}
              className="mx-auto mt-5 w-full max-w-[220px] rounded-xl border border-white/10 shadow-[0_20px_50px_rgba(0,0,0,0.5)]"
            />
            <h3 className="mt-4! text-lg! font-bold! leading-tight! tracking-tight! text-white">
              {selected.title_ru}
            </h3>
            {selected.director && (
              <p className="mt-2! text-xs text-zinc-500">
                <span className="text-zinc-400">Режиссёр:</span>{" "}
                {selected.director.name}
              </p>
            )}
            {!!selected.cast?.length && (
              <p className="mt-2! text-xs text-zinc-500">
                <span className="text-zinc-400">В ролях:</span>{" "}
                {selected.cast
                  .slice(0, 5)
                  .map((person) => person.name)
                  .join(", ")}
              </p>
            )}
          </>
        ) : (
          <div className="mt-5 flex flex-col items-center gap-3 rounded-xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center">
            <FilmIcon className="size-8 text-zinc-600" aria-hidden="true" />
            <p className="text-xs leading-relaxed text-zinc-500">
              Выбери фильм в TMDB или заполни карточку вручную — здесь появится
              превью.
            </p>
          </div>
        )}
        <div className="mt-5 space-y-3 border-t border-white/5 pt-5 text-xs leading-relaxed text-zinc-500">
          <p>
            Заявка сначала появится в разделе «Мои заявки». После одобрения
            карточка попадёт в общий каталог.
          </p>
          <p className="mt-3!">
            Статус и причина отклонения всегда доступны автору.
          </p>
        </div>
        <Link
          href="/moderation"
          className="group mt-5 inline-flex items-center gap-2 text-sm font-medium text-gold transition-colors hover:text-gold-hover"
        >
          Посмотреть заявки{" "}
          <ArrowRightIcon
            className="size-4 transition-transform duration-200 group-hover:translate-x-0.5"
            aria-hidden="true"
          />
        </Link>
      </aside>
    </div>
  );
}