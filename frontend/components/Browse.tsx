"use client";
import {
  ArrowRightIcon,
  ArrowUpRightIcon,
  PlusIcon,
} from "@heroicons/react/24/outline";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { type FormEvent } from "react";
import { api } from "@/lib/api";
import {
  Button,
  Empty,
  ErrorState,
  Field,
  Input,
  Loading,
  MediaGrid,
  PageHeading,
  Pagination,
  Select,
} from "./UI";

const tabsBar =
  "flex w-full max-w-full flex-wrap items-center gap-0 border-2 border-white/10 bg-[var(--panel)] sm:w-fit";

const tabBase =
  "inline-flex flex-1 items-center justify-center gap-2 whitespace-nowrap border-r-2 border-white/10 px-5 py-3 font-mono text-[11px] font-black uppercase tracking-widest outline-none transition-[background-color,color,box-shadow] duration-150 ease-out last:border-r-0 sm:flex-none";

const tabActive =
  "active border-r-2 border-white/10 bg-[var(--accent)] text-[var(--bg)] shadow-[4px_4px_0px_0px_var(--text)] sm:shadow-[3px_3px_0px_0px_var(--text)]";

const tabIdle =
  "border-r-2 border-white/10 bg-transparent text-[var(--muted)] hover:bg-white/5 hover:text-[var(--text)]";

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
        eyebrow={local ? "[ КАТАЛОГ СООБЩЕСТВА ]" : "[ ОТКРОЙ НОВУЮ ИСТОРИЮ ]"}
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
          <Link
            className="group inline-flex items-center gap-2 border-2 border-[var(--accent)] bg-[var(--accent)] px-5 py-3 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)] shadow-[4px_4px_0px_0px_var(--text)] transition-all hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[6px_6px_0px_0px_var(--text)] active:translate-x-0 active:translate-y-0 active:shadow-none"
            href="/suggest"
          >
            <PlusIcon className="ui-icon" aria-hidden="true" />
            Предложить фильм
          </Link>
        )}
      </PageHeading>

      <div className="mb-6 flex flex-col gap-3">
        <div className={tabsBar}>
          <Link
            href="/catalog"
            className={`${tabBase} ${!local ? tabActive : tabIdle}`}
          >
            TMDB
          </Link>
          <Link
            href="/library"
            className={`${tabBase} ${local ? tabActive : tabIdle}`}
          >
            Наш каталог
          </Link>
          {local && (
            <Link
              href="/random"
              className={`${tabBase} ${tabIdle} group`}
            >
              Случайный
              <ArrowUpRightIcon className="ui-icon" aria-hidden="true" />
            </Link>
          )}
        </div>

        {!local && (
          <div className={tabsBar}>
            {[
              ["all", "Всё кино"],
              ["movie", "Фильмы"],
              ["tv", "Сериалы"],
            ].map(([value, name]) => (
              <button
                key={value}
                className={`${tabBase} ${kind === value ? tabActive : tabIdle}`}
                onClick={() => update({ type: value, page: "1" })}
              >
                {name}
              </button>
            ))}
          </div>
        )}
      </div>

      <form
        className="relative mb-8 grid grid-cols-1 gap-4 border-2 border-white/10 bg-[var(--panel)] p-6 shadow-[8px_8px_0px_0px_var(--accent)] sm:grid-cols-2 lg:grid-cols-12"
        onSubmit={submit}
        key={`${local}-${query}-${typeId}-${genreId}-${yearFrom}-${yearTo}-${sort}`}
      >
        {/* Solid accent rule — ticket stub edge */}
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-1 bg-[var(--accent)]"
          aria-hidden="true"
        />

        <div
          className={
            local ? "sm:col-span-2 lg:col-span-4" : "sm:col-span-2 lg:col-span-9"
          }
        >
          <Field label="Поиск" hint={local ? undefined : "Минимум 2 символа"}>
            <Input
              name="q"
              placeholder={
                local ? "Название в каталоге" : "Название фильма или сериала"
              }
              defaultValue={query}
              minLength={local ? 1 : 2}
              maxLength={150}
            />
          </Field>
        </div>

        {local && (
          <>
            <div className="lg:col-span-2">
              <Field label="Тип">
                <Select name="type_id" defaultValue={typeId || ""}>
                  <option value="">Все типы</option>
                  {types.data?.map((type) => (
                    <option value={type.id} key={type.id}>
                      {type.name_ru}
                    </option>
                  ))}
                </Select>
              </Field>
            </div>
            <div className="lg:col-span-2">
              <Field label="Жанр">
                <Select name="genre_ids" defaultValue={genreId || ""}>
                  <option value="">Все жанры</option>
                  {genres.data?.map((genre) => (
                    <option value={genre.id} key={genre.id}>
                      {genre.name_ru}
                    </option>
                  ))}
                </Select>
              </Field>
            </div>
            <div className="lg:col-span-2">
              <Field label="Год от">
                <Input
                  type="number"
                  name="year_from"
                  min={1800}
                  max={2200}
                  defaultValue={yearFrom}
                  placeholder="Любой"
                />
              </Field>
            </div>
            <div className="lg:col-span-2">
              <Field label="Год до">
                <Input
                  type="number"
                  name="year_to"
                  min={1800}
                  max={2200}
                  defaultValue={yearTo}
                  placeholder="Любой"
                />
              </Field>
            </div>
            <div className="sm:col-span-2 lg:col-span-4">
              <Field label="Сортировать">
                <Select name="sort_by" defaultValue={sort}>
                  <option value="created_at">Недавно добавленные</option>
                  <option value="release_date">Новые релизы</option>
                  <option value="title_ru">По названию</option>
                  <option value="avg_rating">По оценке</option>
                </Select>
              </Field>
            </div>
          </>
        )}

        <div className="flex flex-col gap-2 sm:col-span-2 lg:col-span-3 lg:col-start-10">
          <span
            className="hidden select-none font-mono text-[11px] uppercase tracking-widest leading-[1.65] opacity-0 lg:block"
            aria-hidden="true"
          >
            &nbsp;
          </span>
          <Button variant="primary" type="submit" className="group w-full">
            Найти
            <ArrowRightIcon className="ui-icon" aria-hidden="true" />
          </Button>
        </div>
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
            <Link
              className="inline-flex items-center gap-2 border-2 border-[var(--accent)] bg-[var(--accent)] px-5 py-3 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)] shadow-[4px_4px_0px_0px_var(--text)] transition-all hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[6px_6px_0px_0px_var(--text)] active:translate-x-0 active:translate-y-0 active:shadow-none"
              href="/suggest"
            >
              Предложить фильм
            </Link>
          )}
        </Empty>
      )}
    </>
  );
}