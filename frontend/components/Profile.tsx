"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { api, errorMessage } from "@/lib/api";
import { RequireAuth, useAuth } from "./Auth";
import {
  Artwork,
  Empty,
  ErrorState,
  Field,
  Loading,
  MediaCard,
  PageHeading,
} from "./UI";

export default function Profile({
  statsOnly = false,
}: {
  statsOnly?: boolean;
}) {
  const { user } = useAuth();
  const data = useQuery({
    queryKey: ["profile", user?.id],
    queryFn: api.profile,
    enabled: !!user,
  });
  const profile = data.data;
  return (
    <RequireAuth>
      {statsOnly ? (
        <PageHeading
          eyebrow="ТВОЯ СТАТИСТИКА"
          title="История в цифрах"
          description="Каждая оценка и просмотренная серия — часть твоего дневника кино."
        />
      ) : (
        user && (
          <div className="profile-header panel">
            <Artwork src={user.avatar_url} alt={user.name} className="avatar" />
            <div>
              <span className="eyebrow">ТВОЙ ПРОФИЛЬ</span>
              <h1>{user.name}</h1>
              <p>
                @{user.login} · {user.email}
              </p>
            </div>
            <div className="profile-actions">
              <Link className="button secondary" href="/profile/edit">
                Редактировать
              </Link>
              <Link className="button" href="/suggest">
                Предложить фильм
              </Link>
              <Link className="button secondary" href="/moderation">
                {["admin", "moderator"].includes(user.role)
                  ? "Модерация"
                  : "Мои заявки"}
              </Link>
            </div>
          </div>
        )
      )}
      {data.isPending ? (
        <Loading />
      ) : data.error ? (
        <ErrorState error={data.error} retry={() => data.refetch()} />
      ) : (
        profile && (
          <>
            <div className="stats-grid">
              {[
                [profile.stats.total, "В личном списке"],
                [profile.stats.watched, "Просмотрено"],
                [profile.stats.avg_rating.toFixed(1), "Средняя оценка"],
                [profile.stats.episodes_watched, "Серий просмотрено"],
              ].map(([value, name]) => (
                <div className="stat panel" key={name}>
                  <strong>{value}</strong>
                  <span>{name}</span>
                </div>
              ))}
            </div>
            <div className="detail-meta">
              <span className="pill">{profile.stats.movies} фильмов</span>
              <span className="pill">{profile.stats.series} сериалов</span>
              <span className="pill">{profile.stats.rated} оценок</span>
              <span className="pill">
                {profile.stats.collections} коллекций
              </span>
            </div>
            <div className="stats-columns">
              <section className="panel">
                <h2>Статусы просмотра</h2>
                {profile.stats.statuses.length ? (
                  profile.stats.statuses.map((status) => (
                    <div className="chart-row" key={status.name}>
                      <span>{status.name}</span>
                      <div className="progress-bar">
                        <span
                          style={{
                            width: `${(status.count / Math.max(1, profile.stats.total)) * 100}%`,
                          }}
                        />
                      </div>
                      <b>{status.count}</b>
                    </div>
                  ))
                ) : (
                  <p className="description">
                    Добавь первые фильмы в свой список.
                  </p>
                )}
              </section>
              <section className="panel">
                <h2>Любимые жанры</h2>
                {profile.top_genres.length ? (
                  profile.top_genres.map((genre) => (
                    <div className="chart-row" key={genre.name_ru}>
                      <span>{genre.name_ru}</span>
                      <div className="progress-bar">
                        <span
                          style={{
                            width: `${(genre.count / Math.max(...profile.top_genres.map((g) => g.count))) * 100}%`,
                          }}
                        />
                      </div>
                      <b>{genre.count}</b>
                    </div>
                  ))
                ) : (
                  <p className="description">
                    Жанры появятся после загрузки карточек твоих фильмов.
                  </p>
                )}
              </section>
            </div>
            {profile.recent_activity.length ? (
              <section className="section">
                <div className="section-heading">
                  <h2>Недавно добавлено</h2>
                  <Link href="/entries">Весь список →</Link>
                </div>
                <div className="media-grid">
                  {profile.recent_activity.map((entry) => (
                    <MediaCard
                      key={entry.id}
                      media={entry.media}
                      rating={entry.rating}
                      caption={entry.status?.name_ru}
                    />
                  ))}
                </div>
              </section>
            ) : (
              <Empty title="Начни свою историю">
                <Link className="button" href="/catalog">
                  Найти фильм
                </Link>
              </Empty>
            )}
            {!!profile.top_rated.length && (
              <section className="section">
                <div className="section-heading">
                  <h2>Твои высокие оценки</h2>
                  <Link href="/entries">Мой список →</Link>
                </div>
                <div className="media-grid">
                  {profile.top_rated.map((entry) => (
                    <MediaCard
                      key={entry.id}
                      media={entry.media}
                      rating={entry.rating}
                    />
                  ))}
                </div>
              </section>
            )}
          </>
        )
      )}
    </RequireAuth>
  );
}

export function EditProfile() {
  const { user, setUser } = useAuth();
  const cache = useQueryClient();
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const avatar = form.get("avatar");
    if (avatar instanceof File && !avatar.size) form.delete("avatar");
    if (!form.get("password")) {
      form.delete("password");
      form.delete("password_confirmation");
      form.delete("current_password");
    }
    if (form.get("remove_avatar")) form.set("remove_avatar", "1");
    setBusy(true);
    try {
      const result = await api.updateProfile(form);
      setUser(result.user);
      await cache.invalidateQueries({ queryKey: ["profile"] });
      toast.success("Профиль сохранён");
    } catch (error) {
      toast.error(errorMessage(error));
    } finally {
      setBusy(false);
    }
  };
  return (
    <RequireAuth>
      <PageHeading eyebrow="НАСТРОЙКИ АККАУНТА" title="Твой профиль" />
      <div className="edit-panel panel">
        {user && (
          <form className="form-stack" onSubmit={submit}>
            <div className="form-row">
              <Field label="Имя">
                <input
                  name="name"
                  defaultValue={user.name}
                  required
                  maxLength={100}
                  autoComplete="name"
                />
              </Field>
              <Field label="Логин">
                <input
                  name="login"
                  defaultValue={user.login}
                  required
                  minLength={3}
                  maxLength={50}
                  autoComplete="username"
                />
              </Field>
            </div>
            <Field label="Email">
              <input
                name="email"
                type="email"
                defaultValue={user.email}
                required
                autoComplete="email"
              />
            </Field>
            <Field label="Аватар" hint="JPEG, PNG или WebP, до 5 МБ">
              <input
                name="avatar"
                type="file"
                accept="image/jpeg,image/png,image/webp"
              />
            </Field>
            {user.avatar_url && (
              <label className="check-label">
                <input type="checkbox" name="remove_avatar" />
                Удалить аватар
              </label>
            )}
            <h2>Изменить пароль</h2>
            <Field label="Текущий пароль">
              <input
                name="current_password"
                type="password"
                autoComplete="current-password"
              />
            </Field>
            <div className="form-row">
              <Field label="Новый пароль">
                <input
                  name="password"
                  type="password"
                  minLength={8}
                  autoComplete="new-password"
                />
              </Field>
              <Field label="Повтори новый пароль">
                <input
                  name="password_confirmation"
                  type="password"
                  minLength={8}
                  autoComplete="new-password"
                />
              </Field>
            </div>
            <div className="form-actions">
              <button className="button" disabled={busy}>
                {busy ? "Сохраняем…" : "Сохранить профиль"}
              </button>
              <Link href="/profile" className="button secondary">
                Назад
              </Link>
            </div>
          </form>
        )}
      </div>
    </RequireAuth>
  );
}
