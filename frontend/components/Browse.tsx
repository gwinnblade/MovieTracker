"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { type FormEvent } from "react";
import { api } from "@/lib/api";
import {
  Empty,
  ErrorState,
  Field,
  Loading,
  MediaGrid,
  PageHeading,
  Pagination,
} from "./UI";

export default function Browse({ local = false }: { local?: boolean }) {
  const params = useSearchParams();
  const router = useRouter();
  const path = usePathname();
  const query = params.get("q") || "";
  const kind = ["movie", "tv"].includes(params.get("type") || "")
    ? params.get("type")!
    : "all";
  const page = Math.max(1, Number(params.get("page")) || 1);
  const typeId = Number(params.get("type_id")) || undefined;
  const genreId = params.get("genre_ids") || undefined;
  const yearFrom = params.get("year_from") || undefined;
  const yearTo = params.get("year_to") || undefined;
  const sort = params.get("sort_by") || "created_at";
  const update = (updates: Record<string, string>) => {
    const next = new URLSearchParams(params.toString());
    for (const [key, value] of Object.entries(updates)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    router.push(path + "?" + next.toString(), { scroll: false });
  };
  const data = useQuery({
    queryKey: [
      "browse",
      local,
      query,
      kind,
      page,
      typeId,
      genreId,
      yearFrom,
      yearTo,
      sort,
    ],
    queryFn: () =>
      local
        ? api.catalog({
            search: query || undefined,
            type_id: typeId,
            genre_ids: genreId,
            year_from: yearFrom,
            year_to: yearTo,
            sort_by: sort,
            sort_order: sort === "title_ru" ? "asc" : "desc",
            page,
          })
        : query.length >= 2
          ? api.search({ query, type: kind, page })
          : api.trending({ type: kind, page }),
  });
  const types = useQuery({
    queryKey: ["types"],
    queryFn: () => api.references("types"),
    enabled: local,
  });
  const genres = useQuery({
    queryKey: ["genres"],
    queryFn: () => api.references("genres"),
    enabled: local,
  });
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const values: Record<string, string> = { page: "1" };
    for (const [key, value] of form.entries())
      values[key] = String(value).trim();
    update(values);
  };
  return (
    <>
      <PageHeading
        eyebrow={local ? "КАТАЛОГ СООБЩЕСТВА" : "ОТКРОЙ НОВУЮ ИСТОРИЮ"}
        title={
          local
            ? "Проверенное кино"
            : query
              ? `Поиск: ${query}`
              : "Что посмотрим?"
        }
        description={
          local
            ? "Фильмы, сериалы, аниме и мультфильмы, добавленные после модерации."
            : "Фильмы и сериалы из TMDB. Сохрани то, что хочется посмотреть."
        }
      >
        {local && (
          <Link className="button" href="/suggest">
            + Предложить фильм
          </Link>
        )}
      </PageHeading>
      <div className="tabs">
        <Link href="/catalog" className={!local ? "active" : ""}>
          TMDB
        </Link>
        <Link href="/library" className={local ? "active" : ""}>
          Наш каталог
        </Link>
        {local && <Link href="/random">Случайный фильм ↗</Link>}
      </div>
      {!local && (
        <div className="tabs">
          {[
            ["all", "Всё кино"],
            ["movie", "Фильмы"],
            ["tv", "Сериалы"],
          ].map(([value, name]) => (
            <button
              key={value}
              className={kind === value ? "active" : ""}
              onClick={() => update({ type: value, page: "1" })}
            >
              {name}
            </button>
          ))}
        </div>
      )}
      <form
        className="filters"
        onSubmit={submit}
        key={`${local}-${query}-${typeId}-${genreId}-${yearFrom}-${yearTo}-${sort}`}
      >
        <Field label="Поиск" hint={local ? undefined : "Минимум 2 символа"}>
          <input
            name="q"
            placeholder={
              local ? "Название в каталоге" : "Название фильма или сериала"
            }
            defaultValue={query}
            minLength={local ? 1 : 2}
            maxLength={150}
          />
        </Field>
        {local && (
          <>
            <Field label="Тип">
              <select name="type_id" defaultValue={typeId || ""}>
                <option value="">Все типы</option>
                {types.data?.map((type) => (
                  <option value={type.id} key={type.id}>
                    {type.name_ru}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Жанр">
              <select name="genre_ids" defaultValue={genreId || ""}>
                <option value="">Все жанры</option>
                {genres.data?.map((genre) => (
                  <option value={genre.id} key={genre.id}>
                    {genre.name_ru}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Год от">
              <input
                type="number"
                name="year_from"
                min={1800}
                max={2200}
                defaultValue={yearFrom}
                placeholder="Любой"
              />
            </Field>
            <Field label="Год до">
              <input
                type="number"
                name="year_to"
                min={1800}
                max={2200}
                defaultValue={yearTo}
                placeholder="Любой"
              />
            </Field>
            <Field label="Сортировать">
              <select name="sort_by" defaultValue={sort}>
                <option value="created_at">Недавно добавленные</option>
                <option value="release_date">Новые релизы</option>
                <option value="title_ru">По названию</option>
                <option value="avg_rating">По оценке</option>
              </select>
            </Field>
          </>
        )}
        <button className="button" type="submit">
          Найти →
        </button>
      </form>
      {data.isPending ? (
        <Loading
          text={local ? "Загрузка каталога…" : "Получаем кино из TMDB…"}
        />
      ) : data.error ? (
        <ErrorState error={data.error} retry={() => data.refetch()} />
      ) : data.data?.data.length ? (
        <>
          <MediaGrid items={data.data.data} />
          <Pagination
            page={data.data.current_page}
            last={data.data.last_page}
            total={data.data.total}
            onChange={(value) => update({ page: String(value) })}
          />
        </>
      ) : (
        <Empty
          title={query ? "Ничего не найдено" : "Каталог ждёт первые фильмы"}
        >
          <p>
            {query
              ? "Попробуй другое название или сбрось фильтры."
              : "Отправь фильм на модерацию — после одобрения он появится здесь."}
          </p>
          {local && (
            <Link className="button" href="/suggest">
              Предложить фильм
            </Link>
          )}
        </Empty>
      )}
    </>
  );
}
