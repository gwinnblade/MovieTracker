"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useAuth } from "./Auth";
import { Artwork, ErrorState, Loading, MediaCard, MediaGrid } from "./UI";

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
  return (
    <>
      <section className="hero">
        <div>
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
            <Link className="button" href={user ? "/entries" : "/register"}>
              {user ? "Мой список просмотров" : "Начать свою историю"}{" "}
              <span>↗</span>
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
        <div className="feature">
          <span>◈</span>
          <h3>Всё кино под рукой</h3>
          <p>
            Поиск фильмов и сериалов в TMDB и каталог, который пополняет
            сообщество.
          </p>
        </div>
        <div className="feature">
          <span>☆</span>
          <h3>Оценки и прогресс</h3>
          <p>
            Личные оценки, заметки, просмотренные сезоны и записи к каждой
            серии.
          </p>
        </div>
        <div className="feature">
          <span>▧</span>
          <h3>Коллекции с характером</h3>
          <p>Собирай подборки для себя и делись ими по публичной ссылке.</p>
        </div>
      </div>
      {!!profile.data?.continue_watching.length && (
        <section className="section">
          <div className="section-heading">
            <h2>Продолжить просмотр</h2>
            <Link href="/entries">Мой список →</Link>
          </div>
          <div className="media-grid">
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
        </section>
      )}
      {!!profile.data?.recent_activity.length && (
        <section className="section">
          <div className="section-heading">
            <h2>Недавно в твоём списке</h2>
            <Link href="/entries">Все записи →</Link>
          </div>
          <div className="media-grid">
            {profile.data.recent_activity.map((entry) => (
              <MediaCard
                key={entry.id}
                media={entry.media}
                rating={entry.rating}
              />
            ))}
          </div>
        </section>
      )}
      <section className="section">
        <div className="section-heading">
          <h2>Фильмы недели</h2>
          <Link href="/catalog">Открыть TMDB →</Link>
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
      {!!recommendations.data?.data.length && (
        <section className="section">
          <div className="section-heading">
            <h2>Открой новые истории</h2>
            <Link href="/catalog">Ещё кино →</Link>
          </div>
          <MediaGrid items={recommendations.data.data} />
        </section>
      )}
    </>
  );
}
