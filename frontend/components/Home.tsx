"use client";
import Link from "next/link";
import {
  ArrowRightIcon,
  ArrowUpRightIcon,
  FilmIcon,
} from "@heroicons/react/24/outline";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useAuth } from "./Auth";
import { Artwork, ErrorState, Loading, MediaCard } from "./UI";

const GENRES_MOCK = [
  "ДРАМА",
  "КОМЕДИЯ",
  "ФАНТАСТИКА",
  "ТРИЛЛЕР",
  "АНИМЕ",
  "ДОКУМЕНТАЛЬНОЕ",
  "УЖАСЫ",
  "МЕЛОДРАМА",
];

/* ---- Shared brutalist vocabulary (matches UI.tsx page zero) ---- */

const STAMP =
  "inline-block border-2 border-[var(--bg)] bg-[var(--accent)] px-3 py-1 " +
  "font-mono text-[11px] font-bold uppercase tracking-widest text-[var(--bg)]! " +
  "shadow-[3px_3px_0px_0px_var(--text)]";

const KICKER = "font-mono text-xs uppercase tracking-widest text-[var(--accent)]";

const RULE_HEADING =
  "mb-8 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-2 " +
  "border-b-2 border-white/20 pb-4";

const HEADING =
  "text-3xl font-black uppercase tracking-tighter text-[var(--text)] sm:text-4xl";

const GRID5 = "grid grid-cols-2 gap-6 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5";

const CTA_PRIMARY =
  "inline-flex items-center gap-3 border-2 border-[var(--accent)] bg-[var(--accent)] " +
  "px-6 py-4 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)] " +
  "shadow-[4px_4px_0px_0px_var(--text)] " +
  "transition-[transform,box-shadow] duration-150 ease-out " +
  "hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[6px_6px_0px_0px_var(--text)] " +
  "active:translate-x-0 active:translate-y-0 active:shadow-none " +
  "disabled:opacity-40 disabled:cursor-not-allowed " +
  "disabled:hover:translate-x-0 disabled:hover:translate-y-0 disabled:hover:shadow-[4px_4px_0px_0px_var(--text)] " +
  "focus-visible:outline-2 focus-visible:outline-[var(--text)] focus-visible:outline-offset-2";


const CTA_SECONDARY =
  "inline-flex items-center gap-3 border-2 border-white/20 bg-transparent " +
  "px-6 py-4 text-sm font-bold uppercase tracking-wider text-[var(--text)] " +
  "shadow-[4px_4px_0px_0px_rgba(255,255,255,0.12)] " +
  "transition-[transform,box-shadow,border-color] duration-150 ease-out " +
  "hover:-translate-x-0.5 hover:-translate-y-0.5 hover:border-white/40 " +
  "hover:shadow-[6px_6px_0px_0px_rgba(255,255,255,0.18)] " +
  "active:translate-x-0 active:translate-y-0 active:shadow-none " +
  "focus-visible:outline-2 focus-visible:outline-[var(--accent)] focus-visible:outline-offset-2";

const SECTION_LINK =
  "group flex items-center gap-2 font-mono text-xs uppercase tracking-widest " +
  "text-[var(--muted)] transition-colors duration-150 hover:text-[var(--accent)]";

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

  const stats = [
    {
      label: "Записей в журнале",
      value: profile.data?.recent_activity?.length ?? 0,
    },
    { label: "В коллекциях", value: "—" },
    { label: "Средняя оценка", value: "—" },
  ];

  return (
    <>
      {/* HERO */}
      <section className="border-b-2 border-white/20 bg-[var(--bg)]">
        <div className="mx-auto grid max-w-[1440px] grid-cols-1 gap-10 px-6 py-16 md:grid-cols-12 md:px-12 md:py-24">
          <div className="flex flex-col justify-center md:col-span-7">
            <span className={STAMP}>Твой киножурнал</span>
            <h1 className="mt-8 text-5xl font-black uppercase leading-[0.9] tracking-tighter text-[var(--text)] sm:text-7xl md:text-8xl">
              Хорошие <br />
              истории <br />
              <span className="mt-2 inline-block bg-[var(--accent)] px-3 text-[var(--bg)]">
                хочется сохранить.
              </span>
            </h1>
            <p className="mt-8 max-w-lg text-lg leading-relaxed text-[var(--muted)]">
              Собирай любимые фильмы, отмечай просмотренное и продолжай сериалы с
              той самой серии. Без алгоритмов и случайных рекомендаций.
            </p>
            <div className="mt-10 flex flex-wrap gap-4">
              <Link className={CTA_SECONDARY} href={user ? "/entries" : "/register"}>
                {user ? "Мой список" : "Начать историю"}
                <ArrowUpRightIcon
                  className="h-5 w-5 transition-transform duration-150 group-hover:translate-x-1 group-hover:-translate-y-1"
                  aria-hidden="true"
                />
              </Link>
              <Link className={CTA_SECONDARY} href="/catalog">
                Найти фильм
              </Link>
            </div>
          </div>

          {/* Framed poster — one frame, one hard shadow */}
          <div className="flex items-center justify-center md:col-span-5">
            <div className="relative w-full max-w-[340px]">
              <span className={`${STAMP} absolute -top-3 -right-3 z-10`}>
                Сейчас в тренде
              </span>
              {trends.data?.data[0] ? (
                <div className="border-2 border-white/20 shadow-[8px_8px_0px_0px_var(--accent)]">
                  <Artwork
                    src={trends.data.data[0].poster_url}
                    alt={trends.data.data[0].title_ru || "Trending movie poster"}
                    priority
                    className="aspect-[2/3] w-full"
                  />
                </div>
              ) : (
                <div className="relative flex aspect-[2/3] w-full flex-col items-center justify-center gap-3 border-2 border-dashed border-white/20 bg-[var(--panel)] shadow-[8px_8px_0px_0px_var(--accent)]">
                  <FilmIcon className="h-10 w-10 text-[var(--muted)]" aria-hidden="true" />
                  <span className="font-mono text-[10px] uppercase tracking-widest text-[var(--subtle)]">
                    Постер скоро
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* FEATURES — RULED LIST */}
      <section className="border-b-2 border-white/20 bg-[var(--bg)]">
        <div className="mx-auto max-w-[1440px] px-6 md:px-12">
          <div className="grid grid-cols-1 md:grid-cols-3">
            <div className="border-b-2 border-white/20 p-8 md:border-b-0 md:border-r-2">
              <span className={KICKER}>01 / Каталог</span>
              <h3 className="mt-4 text-2xl font-black uppercase tracking-tight text-[var(--text)]">
                Всё кино под рукой
              </h3>
              <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
                Поиск фильмов и сериалов в TMDB и каталог, который пополняет
                сообщество.
              </p>
            </div>
            <div className="border-b-2 border-white/20 p-8 md:border-b-0 md:border-r-2">
              <span className={KICKER}>02 / Прогресс</span>
              <h3 className="mt-4 text-2xl font-black uppercase tracking-tight text-[var(--text)]">
                Оценки и заметки
              </h3>
              <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
                Личные оценки, заметки, просмотренные сезоны и записи к каждой
                серии.
              </p>
            </div>
            <div className="p-8">
              <span className={KICKER}>03 / Архив</span>
              <h3 className="mt-4 text-2xl font-black uppercase tracking-tight text-[var(--text)]">
                Коллекции
              </h3>
              <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
                Собирай подборки для себя и делись ими по публичной ссылке.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* TICKER / GENRES */}
      <section className="border-b-2 border-white/20 bg-[var(--panel)]">
        <div className="flex overflow-hidden py-4">
          <div className="flex shrink-0 animate-[marquee_30s_linear_infinite] gap-4 px-4 motion-reduce:[animation:none]">
            {[...GENRES_MOCK, ...GENRES_MOCK].map((genre, i) => (
              <Link
                key={`${genre}-${i}`}
                href={"/catalog?genre=" + encodeURIComponent(genre)}
                aria-hidden={i >= GENRES_MOCK.length}
                tabIndex={i >= GENRES_MOCK.length ? -1 : undefined}
                className="shrink-0 border-2 border-white/20 bg-[var(--bg)] px-4 py-2 font-mono text-xs font-bold uppercase tracking-wider text-[var(--text)] transition-colors duration-150 hover:border-[var(--accent)] hover:text-[var(--accent)]"
              >
                {genre}
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* AUTH CTA */}
      {!user && (
        <section className="border-b-2 border-white/20 bg-[var(--bg)]">
          <div className="mx-auto max-w-[1440px] px-6 py-20 md:px-12">
            <div className="relative border-2 border-white/20 bg-[var(--panel)] p-10 shadow-[8px_8px_0px_0px_var(--accent)] md:p-16">
              <span className={`${STAMP} absolute -top-3 left-8`}>
                Доступ закрыт
              </span>
              <div className="max-w-2xl">
                <h2 className="text-4xl font-black uppercase leading-tight tracking-tighter text-[var(--text)] sm:text-5xl">
                  Начни свой <br /> дневник кино
                </h2>
                <p className="mt-6 text-lg leading-relaxed text-[var(--muted)]">
                  Сохраняй фильмы, ставь оценки, продолжай сериалы с той же
                  серии. Никакой рекламы и алгоритмов.
                </p>
                <div className="mt-10 flex flex-wrap gap-4">
                  <Link href="/register" className={CTA_PRIMARY}>
                    Создать аккаунт
                  </Link>
                  <Link href="/login" className={CTA_SECONDARY}>
                    Войти
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* CONTINUE WATCHING */}
      {!!profile.data?.continue_watching.length && (
        <section className="border-b-2 border-white/20 bg-[var(--bg)]">
          <div className="mx-auto max-w-[1440px] px-6 py-16 md:px-12">
            <div className={RULE_HEADING}>
              <h2 className={HEADING}>Продолжить просмотр</h2>
              <Link href="/entries" className={SECTION_LINK}>
                Мой список{" "}
                <ArrowRightIcon
                  className="h-4 w-4 transition-transform duration-150 group-hover:translate-x-1"
                  aria-hidden="true"
                />
              </Link>
            </div>
            <div className={GRID5}>
              {profile.data.continue_watching.map((entry) => (
                <MediaCard
                  key={entry.id}
                  media={entry.media}
                  rating={entry.rating}
                  caption={
                    entry.episodes_watched
                      ? `${entry.episodes_watched} серий`
                      : "Смотрю"
                  }
                />
              ))}
            </div>
          </div>
        </section>
      )}

      {/* RECENT ACTIVITY */}
      {!!profile.data?.recent_activity.length && (
        <section className="border-b-2 border-white/20 bg-[var(--bg)]">
          <div className="mx-auto max-w-[1440px] px-6 py-16 md:px-12">
            <div className={RULE_HEADING}>
              <h2 className={HEADING}>Недавно в списке</h2>
              <Link href="/entries" className={SECTION_LINK}>
                Все записи{" "}
                <ArrowRightIcon
                  className="h-4 w-4 transition-transform duration-150 group-hover:translate-x-1"
                  aria-hidden="true"
                />
              </Link>
            </div>
            <div className={GRID5}>
              {profile.data.recent_activity.map((entry) => (
                <MediaCard
                  key={entry.id}
                  media={entry.media}
                  rating={entry.rating}
                />
              ))}
            </div>
          </div>
        </section>
      )}

      {/* STATS */}
      {!!user && (
        <section className="border-b-2 border-white/20 bg-[var(--bg)]">
          <div className="mx-auto max-w-[1440px] px-6 py-16 md:px-12">
            <div className={RULE_HEADING}>
              <div>
                <span className={KICKER}>Твой дневник в цифрах</span>
                <h2 className={`mt-2 ${HEADING}`}>Статистика</h2>
              </div>
              <Link href="/stats" className={SECTION_LINK}>
                Подробнее{" "}
                <ArrowRightIcon
                  className="h-4 w-4 transition-transform duration-150 group-hover:translate-x-1"
                  aria-hidden="true"
                />
              </Link>
            </div>
            <div className="grid grid-cols-1 gap-6 sm:grid-cols-3">
              {stats.map((stat) => (
                <div
                  key={stat.label}
                  className="border-2 border-white/20 bg-[var(--panel)] p-6 shadow-[6px_6px_0px_0px_rgba(255,255,255,0.08)]"
                >
                  <span className="font-mono text-xs uppercase tracking-widest text-[var(--muted)]">
                    {stat.label}
                  </span>
                  <div className="mt-4 text-5xl font-black tracking-tighter text-[var(--text)]">
                    {stat.value}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {/* TRENDS */}
      <section className="border-b-2 border-white/20 bg-[var(--bg)]">
        <div className="mx-auto max-w-[1440px] px-6 py-16 md:px-12">
          <div className={RULE_HEADING}>
            <h2 className={HEADING}>Фильмы недели</h2>
            <Link href="/catalog" className={SECTION_LINK}>
              Открыть TMDB{" "}
              <ArrowRightIcon
                className="h-4 w-4 transition-transform duration-150 group-hover:translate-x-1"
                aria-hidden="true"
              />
            </Link>
          </div>
          {trends.isPending ? (
            <Loading />
          ) : trends.error ? (
            <ErrorState error={trends.error} retry={() => trends.refetch()} />
          ) : (
            <div className={GRID5}>
              {trends.data?.data.slice(0, 10).map((media) => (
                <MediaCard key={media.tmdb_id} media={media} />
              ))}
            </div>
          )}
        </div>
      </section>

      {/* COMMUNITY */}
      {!!community.data?.data.length && (
        <section className="border-b-2 border-white/20 bg-[var(--bg)]">
          <div className="mx-auto max-w-[1440px] px-6 py-16 md:px-12">
            <div className={RULE_HEADING}>
              <h2 className={HEADING}>Проверено сообществом</h2>
              <Link href="/library" className={SECTION_LINK}>
                Весь каталог{" "}
                <ArrowRightIcon
                  className="h-4 w-4 transition-transform duration-150 group-hover:translate-x-1"
                  aria-hidden="true"
                />
              </Link>
            </div>
            <div className={GRID5}>
              {community.data.data.slice(0, 5).map((media) => (
                <MediaCard
                  key={media.id || `${media.tmdb_type}-${media.tmdb_id}`}
                  media={media}
                />
              ))}
            </div>
          </div>
        </section>
      )}

      {/* RANDOM CTA */}
      <section className="border-b-2 border-white/20 bg-[var(--bg)]">
        <div className="mx-auto max-w-[1440px] px-6 py-20 md:px-12">
          <div className="relative border-2 border-[var(--accent)] bg-[var(--accent)] p-10 shadow-[8px_8px_0px_0px_var(--text)] md:p-16">
            <span
              className={`${STAMP} absolute -top-3 left-8 !border-[var(--accent)] !bg-[var(--bg)] !text-[var(--accent)] !shadow-[3px_3px_0px_0px_var(--text)]`}
            >
              Случайный выбор
            </span>
            <div className="flex flex-col gap-8 md:flex-row md:items-center md:justify-between">
              <div className="min-w-0">
                <h2 className="text-4xl font-black uppercase leading-tight tracking-tighter text-[var(--bg)] sm:text-5xl">
                  Не знаешь, <br /> что посмотреть?
                </h2>
                <p className="mt-4 max-w-md text-lg leading-relaxed text-[var(--bg)]/80">
                  Доверься случаю — выберем из проверенного каталога сообщества.
                </p>
              </div>
              <Link
                href="/random"
                className="group inline-flex shrink-0 items-center gap-3 border-2 border-[var(--bg)] bg-[var(--bg)] px-8 py-5 text-sm font-bold uppercase tracking-wider text-[var(--accent)] shadow-[4px_4px_0px_0px_var(--text)] transition-[transform,box-shadow] duration-150 ease-out hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[6px_6px_0px_0px_var(--text)] active:translate-x-0 active:translate-y-0 active:shadow-none focus-visible:outline-2 focus-visible:outline-[var(--bg)] focus-visible:outline-offset-2"
              >
                Крутить рулетку
                <ArrowRightIcon
                  className="h-5 w-5 transition-transform duration-150 group-hover:translate-x-1"
                  aria-hidden="true"
                />
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* RECOMMENDATIONS */}
      {!!recommendations.data?.data.length && (
        <section className="bg-[var(--bg)]">
          <div className="mx-auto max-w-[1440px] px-6 py-16 md:px-12">
            <div className={RULE_HEADING}>
              <h2 className={HEADING}>Открой новые истории</h2>
              <Link href="/catalog" className={SECTION_LINK}>
                Ещё кино{" "}
                <ArrowRightIcon
                  className="h-4 w-4 transition-transform duration-150 group-hover:translate-x-1"
                  aria-hidden="true"
                />
              </Link>
            </div>
            <div className={GRID5}>
              {recommendations.data.data.map((media) => (
                <MediaCard
                  key={media.id || `${media.tmdb_type}-${media.tmdb_id}`}
                  media={media}
                />
              ))}
            </div>
          </div>
        </section>
      )}
    </>
  );
}