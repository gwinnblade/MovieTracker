"use client";

import Link from "next/link";
import {
  ArrowRightIcon,
  ArrowUpRightIcon,
  BookmarkSquareIcon,
  FilmIcon,
  StarIcon,
} from "@heroicons/react/24/outline";
import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { api } from "@/lib/api";
import { useAuth } from "./Auth";
import { Artwork, ErrorState, Loading, MediaCard, MediaGrid } from "./UI";

// TODO: заменить на API
const GENRES_MOCK = [
  "Драма",
  "Комедия",
  "Фантастика",
  "Триллер",
  "Аниме",
  "Документальное",
  "Ужасы",
  "Мелодрама",
];

const shelfClasses =
  "-mx-4 flex snap-x snap-mandatory gap-4 overflow-x-auto px-4 pt-3 pb-2 [&::-webkit-scrollbar]:hidden [scrollbar-width:none]";

const shelfItemClasses =
  "w-[160px] shrink-0 snap-start sm:w-[180px] md:w-[200px]";

const stripClasses =
  "-mx-4 flex snap-x gap-3 overflow-x-auto px-4 pb-2 [&::-webkit-scrollbar]:hidden [scrollbar-width:none]";

function SectionTitle({ children }: { children: ReactNode }) {
  return (
    <h2 className="text-2xl! font-bold! tracking-tight! sm:text-3xl!">
      <span className="mr-3 inline-block h-1.5 w-1.5 rounded-full bg-gold align-middle" />
      {children}
    </h2>
  );
}

export default function Home() {
  const { user } = useAuth();

  const trends = useQuery({
    queryKey: ["trending-home"],
    queryFn: () => api.trending({ type: "movie" }),
  });

  const profile = useQuery({
    queryKey: ["profile", user?.id],
    queryFn: api.profile,
    enabled: !!user,
  });

  const recommendations = useQuery({
    queryKey: ["recommendations", user?.id],
    queryFn: api.recommendations,
    enabled: !!user,
  });

  const community = useQuery({
    queryKey: ["community-home"],
    queryFn: () => api.catalog({ page: 1, sort_by: "created_at" }),
  });

  // TODO: заменить на реальные данные
  const stats = [
    {
      label: "Просмотрено",
      value: profile.data?.recent_activity?.length ?? 0,
    },
    { label: "В коллекциях", value: "—" },
    { label: "Средняя оценка", value: "—" },
  ];

  return (
    <>
      <section className="hero">
        {trends.data?.data[0]?.poster_url && (
          <Artwork
            src={trends.data.data[0].poster_url}
            alt=""
            className="pointer-events-none absolute! inset-y-0 left-0 -z-10 w-[380px] opacity-15 blur-3xl"
          />
        )}
        <div className="hero-copy">
          <span className="eyebrow">ТВОЙ ЛИЧНЫЙ ДНЕВНИК КИНО</span>
          <h1>
            Хорошие истории
            <br />
            хочется <em>сохранить.</em>
          </h1>
          <p>
            Собирай любимые фильмы, отмечай просмотренное и продолжай сериалы с
            той самой серии.
          </p>
          <div className="hero-actions">
            <Link
              className="button hero-primary shadow-[0_8px_24px_rgba(229,169,61,0.15)]!"
              href={user ? "/entries" : "/register"}
            >
              {user ? "Мой список просмотров" : "Начать свою историю"}{" "}
              <ArrowUpRightIcon className="ui-icon" aria-hidden="true" />
            </Link>
            <Link className="button secondary" href="/catalog">
              Найти фильм
            </Link>
          </div>
        </div>
        <div className="hero-posters" aria-hidden="true">
          {(
            trends.data?.data || [
              { title_ru: "" },
              { title_ru: "" },
              { title_ru: "" },
            ]
          )
            .slice(0, 3)
            .map((media, index) => (
              <Artwork key={index} src={media.poster_url} alt="" priority />
            ))}
        </div>
      </section>

      <div className="features">
        <div className="feature group">
          <span className="feature-icon transition-[transform,border-color] duration-300 group-hover:-translate-y-0.5 group-hover:border-gold/20!">
            <FilmIcon aria-hidden="true" />
          </span>
          <div className="feature-copy">
            <h3>Всё кино под рукой</h3>
            <p>
              Поиск фильмов и сериалов в TMDB и каталог, который пополняет
              сообщество.
            </p>
          </div>
        </div>
        <div className="feature group">
          <span className="feature-icon transition-[transform,border-color] duration-300 group-hover:-translate-y-0.5 group-hover:border-gold/20!">
            <StarIcon aria-hidden="true" />
          </span>
          <div className="feature-copy">
            <h3>Оценки и прогресс</h3>
            <p>
              Личные оценки, заметки, просмотренные сезоны и записи к каждой
              серии.
            </p>
          </div>
        </div>
        <div className="feature group">
          <span className="feature-icon transition-[transform,border-color] duration-300 group-hover:-translate-y-0.5 group-hover:border-gold/20!">
            <BookmarkSquareIcon aria-hidden="true" />
          </span>
          <div className="feature-copy">
            <h3>Коллекции с характером</h3>
            <p>Собирай подборки для себя и делись ими по публичной ссылке.</p>
          </div>
        </div>
      </div>

      <section>
        <span className="eyebrow mb-4 block">ИССЛЕДУЙ ПО НАСТРОЕНИЮ</span>
        <div className={stripClasses}>
          {GENRES_MOCK.map((genre) => (
            <Link
              key={genre}
              href={"/catalog?genre=" + encodeURIComponent(genre)}
              className="shrink-0 snap-start rounded-full border border-white/10 bg-white/[0.03] px-5 py-2.5 text-sm whitespace-nowrap text-zinc-300! transition-all duration-300 hover:border-gold/40 hover:bg-gold/5 hover:text-gold!"
            >
              {genre}
            </Link>
          ))}
        </div>
      </section>

      {!user && (
        <section className="relative mt-16 overflow-hidden rounded-3xl border border-white/5 bg-[#151921] p-10 text-center sm:p-14">
          <div
            className="pointer-events-none absolute -top-24 left-1/2 h-64 w-64 -translate-x-1/2 rounded-full bg-gold/10 blur-3xl"
            aria-hidden="true"
          />
          <div className="relative">
            <span className="mx-auto grid size-16 place-items-center rounded-2xl border border-gold/20 bg-gold/10 text-gold">
              <FilmIcon className="size-7" aria-hidden="true" />
            </span>
            <h2 className="mt-6! text-2xl! font-bold! tracking-tight! text-white sm:text-3xl!">
              Начни свой дневник кино
            </h2>
            <p className="mx-auto! mt-3! max-w-md text-zinc-400">
              Сохраняй фильмы, ставь оценки, продолжай сериалы с той же серии.
            </p>
            <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <Link href="/register" className="button w-full sm:w-auto">
                Создать аккаунт
              </Link>
              <Link
                href="/login"
                className="button secondary w-full sm:w-auto"
              >
                Войти
              </Link>
            </div>
          </div>
        </section>
      )}

      {!!profile.data?.continue_watching.length && (
        <section className="mt-16">
          <div className="section-heading mb-8!">
            <SectionTitle>Продолжить просмотр</SectionTitle>
            <Link href="/entries">
              Мой список{" "}
              <ArrowRightIcon className="ui-icon" aria-hidden="true" />
            </Link>
          </div>
          <div className={shelfClasses}>
            {profile.data.continue_watching.map((entry) => (
              <div className={shelfItemClasses} key={entry.id}>
                <MediaCard
                  media={entry.media}
                  rating={entry.rating}
                  caption={
                    entry.episodes_watched
                      ? `${entry.episodes_watched} серий`
                      : "Смотрю"
                  }
                />
              </div>
            ))}
          </div>
        </section>
      )}

      {!!profile.data?.recent_activity.length && (
        <section className="mt-16">
          <div className="section-heading mb-8!">
            <SectionTitle>Недавно в твоём списке</SectionTitle>
            <Link href="/entries">
              Все записи{" "}
              <ArrowRightIcon className="ui-icon" aria-hidden="true" />
            </Link>
          </div>
          <div className={shelfClasses}>
            {profile.data.recent_activity.map((entry) => (
              <div className={shelfItemClasses} key={entry.id}>
                <MediaCard media={entry.media} rating={entry.rating} />
              </div>
            ))}
          </div>
        </section>
      )}

      {!!user && (
        <section className="mt-16">
          <div className="section-heading mb-8!">
            <div>
              <span className="eyebrow mb-2 block">
                ТВОЙ ДНЕВНИК В ЦИФРАХ
              </span>
              <SectionTitle>Твоя статистика</SectionTitle>
            </div>
            <Link href="/stats">
              Моя статистика{" "}
              <ArrowRightIcon className="ui-icon" aria-hidden="true" />
            </Link>
          </div>
          <div className="flex flex-col gap-4 sm:flex-row">
            {stats.map((stat) => (
              <div
                key={stat.label}
                className="flex flex-1 items-baseline gap-3 rounded-2xl border border-white/5 bg-[#151921] px-6 py-4 transition-colors hover:border-gold/20"
              >
                <span className="text-2xl font-bold text-white">
                  {stat.value}
                </span>
                <span className="text-xs tracking-widest text-zinc-500 uppercase">
                  {stat.label}
                </span>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="mt-20">
        <div className="section-heading mb-8!">
          <SectionTitle>Фильмы недели</SectionTitle>
          <Link href="/catalog">
            Открыть TMDB{" "}
            <ArrowRightIcon className="ui-icon" aria-hidden="true" />
          </Link>
        </div>
        {trends.isPending ? (
          <Loading />
        ) : trends.error ? (
          <ErrorState error={trends.error} retry={() => trends.refetch()} />
        ) : (
          <div className="home-grid">
            {trends.data?.data.slice(0, 10).map((media) => (
              <MediaCard key={media.tmdb_id} media={media} />
            ))}
          </div>
        )}
      </section>

      {!!community.data?.data.length && (
        <section className="mt-16">
          <div className="section-heading mb-8!">
            <SectionTitle>Проверено сообществом</SectionTitle>
            <Link href="/library">
              Весь каталог{" "}
              <ArrowRightIcon className="ui-icon" aria-hidden="true" />
            </Link>
          </div>
          <div className="home-grid">
            {community.data.data.slice(0, 5).map((media) => (
              <MediaCard
                key={media.id || `${media.tmdb_type}-${media.tmdb_id}`}
                media={media}
              />
            ))}
          </div>
        </section>
      )}

      <section className="relative mt-20 overflow-hidden rounded-3xl border border-gold/15 bg-gradient-to-br from-[#1a1608] via-[#151921] to-[#0B0E14] p-8 sm:p-12">
        <div
          className="pointer-events-none absolute -top-20 -right-20 h-64 w-64 rounded-full bg-gold/15 blur-3xl"
          aria-hidden="true"
        />
        <div className="relative flex flex-col gap-8 md:flex-row md:items-center md:justify-between">
          <div className="min-w-0">
            <span className="eyebrow">СЛУЧАЙНЫЙ ВЫБОР</span>
            <h2 className="mt-3! text-3xl! font-bold! tracking-tight! text-white sm:text-4xl!">
              Не знаешь, что посмотреть?
            </h2>
            <p className="mt-2! text-zinc-400">
              Доверься случаю — выберем из проверенного каталога сообщества.
            </p>
          </div>
          <Link
            href="/random"
            className="button group shrink-0 shadow-[0_8px_24px_rgba(229,169,61,0.15)]!"
          >
            Выбрать случайный фильм{" "}
            <ArrowRightIcon
              className="ui-icon transition-transform duration-200 group-hover:translate-x-0.5"
              aria-hidden="true"
            />
          </Link>
        </div>
      </section>

      {!!recommendations.data?.data.length && (
        <section className="mt-16">
          <div className="section-heading mb-8!">
            <SectionTitle>Открой новые истории</SectionTitle>
            <Link href="/catalog">
              Ещё кино{" "}
              <ArrowRightIcon className="ui-icon" aria-hidden="true" />
            </Link>
          </div>
          <MediaGrid items={recommendations.data.data} />
        </section>
      )}
    </>
  );
}