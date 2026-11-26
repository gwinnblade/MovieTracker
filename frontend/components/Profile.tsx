"use client";

import {
  ArrowRightIcon,
  BookmarkIcon,
  CheckCircleIcon,
  PencilSquareIcon,
  PlayCircleIcon,
  PlusIcon,
  ShieldCheckIcon,
  StarIcon,
} from "@heroicons/react/24/outline";
import Link from "next/link";
import { useState, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { api, errorMessage } from "@/lib/api";
import { RequireAuth, useAuth } from "./Auth";
import {
  Artwork,
  Button,
  Checkbox,
  Empty,
  ErrorState,
  Field,
  Input,
  Loading,
  MediaCard,
  PageHeading,
} from "./UI";

const shelfClasses =
  "-mx-4 flex snap-x snap-mandatory gap-4 overflow-x-auto px-4 pt-3 pb-2 [&::-webkit-scrollbar]:hidden [scrollbar-width:none]";

const shelfItemClasses = "w-[160px] shrink-0 snap-start sm:w-[180px]";

const shelfLinkClasses =
  "group inline-flex items-center gap-2 text-sm! text-zinc-400! transition-colors hover:text-gold!";

const miniPillClasses =
  "inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-zinc-400";

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
          <div className="relative flex flex-wrap items-center gap-6 overflow-hidden rounded-3xl border border-white/5 bg-gradient-to-br from-[#151921] to-[#0B0E14] p-6 sm:p-8">
            <div
              className="pointer-events-none absolute -top-24 -right-24 size-64 rounded-full bg-gold/10 blur-3xl"
              aria-hidden="true"
            />
            <Artwork
              src={user.avatar_url}
              alt={user.name}
              className="avatar size-24! shrink-0 rounded-full border-2 border-gold/30 shadow-[0_0_30px_rgba(229,169,61,0.2)]!"
            />
            <div className="relative min-w-0 flex-1">
              <span className="eyebrow">ТВОЙ ПРОФИЛЬ</span>
              <h1 className="mt-2! text-3xl! font-bold! tracking-tight! text-white">
                {user.name}
              </h1>
              <p className="mt-1! text-sm text-zinc-400">
                @{user.login} · {user.email}
              </p>
            </div>
            <div className="profile-actions relative">
              <Link className="button secondary" href="/profile/edit">
                <PencilSquareIcon className="size-4" aria-hidden="true" />
                Редактировать
              </Link>
              <Link className="button" href="/suggest">
                <PlusIcon className="size-4" aria-hidden="true" />
                Предложить фильм
              </Link>
              <Link className="button secondary" href="/moderation">
                <ShieldCheckIcon className="size-4" aria-hidden="true" />
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
            <div className="my-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
              {[
                {
                  value: profile.stats.total,
                  name: "В личном списке",
                  icon: BookmarkIcon,
                },
                {
                  value: profile.stats.watched,
                  name: "Просмотрено",
                  icon: CheckCircleIcon,
                },
                {
                  value: profile.stats.avg_rating.toFixed(1),
                  name: "Средняя оценка",
                  icon: StarIcon,
                },
                {
                  value: profile.stats.episodes_watched,
                  name: "Серий просмотрено",
                  icon: PlayCircleIcon,
                },
              ].map(({ value, name, icon: Icon }) => (
                <div
                  key={name}
                  className="group relative overflow-hidden rounded-2xl border border-white/5 bg-gradient-to-br from-[#151921] to-[#0B0E14] p-5 transition-all duration-300 hover:border-gold/20 hover:shadow-[0_0_30px_rgba(229,169,61,0.08)]"
                >
                  <div className="pointer-events-none absolute -top-8 -right-8 size-20 rounded-full bg-gold/5 opacity-0 blur-2xl transition-opacity duration-300 group-hover:opacity-100" />
                  <Icon
                    className="relative mb-3 size-5 text-gold/60"
                    aria-hidden="true"
                  />
                  <strong className="relative block text-4xl leading-none font-bold tracking-tight text-white tabular-nums">
                    {value}
                  </strong>
                  <span className="relative mt-2 block text-xs tracking-widest text-zinc-500 uppercase">
                    {name}
                  </span>
                </div>
              ))}
            </div>

            <div className="detail-meta">
              <span className={miniPillClasses}>
                {profile.stats.movies} фильмов
              </span>
              <span className={miniPillClasses}>
                {profile.stats.series} сериалов
              </span>
              <span className={miniPillClasses}>
                {profile.stats.rated} оценок
              </span>
              <span className={miniPillClasses}>
                {profile.stats.collections} коллекций
              </span>
            </div>

            <div className="my-8 grid gap-5 md:grid-cols-2">
              <section className="rounded-2xl border border-white/5 bg-[#151921] p-6">
                <h2 className="mb-6! text-xl! font-bold! tracking-tight! text-white">
                  Статусы просмотра
                </h2>
                {profile.stats.statuses.length ? (
                  profile.stats.statuses.map((status) => (
                    <div
                      className="mb-4 grid grid-cols-[110px_1fr_40px] items-center gap-3"
                      key={status.name}
                    >
                      <span className="truncate text-sm text-zinc-400">
                        {status.name}
                      </span>
                      <div className="h-2 overflow-hidden rounded-full bg-white/[0.04]">
                        <span
                          className="block h-full rounded-full bg-gradient-to-r from-gold/60 to-gold shadow-[0_0_8px_rgba(229,169,61,0.4)] transition-[width] duration-500"
                          style={{
                            width: `${(status.count / Math.max(1, profile.stats.total)) * 100}%`,
                          }}
                        />
                      </div>
                      <b className="text-right text-sm font-semibold text-white tabular-nums">
                        {status.count}
                      </b>
                    </div>
                  ))
                ) : (
                  <p className="text-sm leading-relaxed text-zinc-500">
                    Добавь первые фильмы в свой список.
                  </p>
                )}
              </section>
              <section className="rounded-2xl border border-white/5 bg-[#151921] p-6">
                <h2 className="mb-6! text-xl! font-bold! tracking-tight! text-white">
                  Любимые жанры
                </h2>
                {profile.top_genres.length ? (
                  profile.top_genres.map((genre) => (
                    <div
                      className="mb-4 grid grid-cols-[110px_1fr_40px] items-center gap-3"
                      key={genre.name_ru}
                    >
                      <span className="truncate text-sm text-zinc-400">
                        {genre.name_ru}
                      </span>
                      <div className="h-2 overflow-hidden rounded-full bg-white/[0.04]">
                        <span
                          className="block h-full rounded-full bg-gradient-to-r from-gold/60 to-gold shadow-[0_0_8px_rgba(229,169,61,0.4)] transition-[width] duration-500"
                          style={{
                            width: `${(genre.count / Math.max(...profile.top_genres.map((g) => g.count))) * 100}%`,
                          }}
                        />
                      </div>
                      <b className="text-right text-sm font-semibold text-white tabular-nums">
                        {genre.count}
                      </b>
                    </div>
                  ))
                ) : (
                  <p className="text-sm leading-relaxed text-zinc-500">
                    Жанры появятся после загрузки карточек твоих фильмов.
                  </p>
                )}
              </section>
            </div>

            {profile.recent_activity.length ? (
              <section className="section">
                <div className="section-heading">
                  <h2 className="text-2xl! font-bold! tracking-tight! text-white">
                    Недавно добавлено
                  </h2>
                  <Link href="/entries" className={shelfLinkClasses}>
                    Весь список{" "}
                    <ArrowRightIcon
                      className="size-4 transition-transform group-hover:translate-x-1"
                      aria-hidden="true"
                    />
                  </Link>
                </div>
                <div className={shelfClasses}>
                  {profile.recent_activity.map((entry) => (
                    <div className={shelfItemClasses} key={entry.id}>
                      <MediaCard
                        media={entry.media}
                        rating={entry.rating}
                        caption={entry.status?.name_ru}
                      />
                    </div>
                  ))}
                </div>
              </section>
            ) : (
              <Empty title="Начни свою историю">
                <Link href="/catalog" className="button">
                  Найти фильм
                </Link>
              </Empty>
            )}

            {!!profile.top_rated.length && (
              <section className="section">
                <div className="section-heading">
                  <h2 className="text-2xl! font-bold! tracking-tight! text-white">
                    Твои высокие оценки
                  </h2>
                  <Link href="/entries" className={shelfLinkClasses}>
                    Мой список{" "}
                    <ArrowRightIcon
                      className="size-4 transition-transform group-hover:translate-x-1"
                      aria-hidden="true"
                    />
                  </Link>
                </div>
                <div className={shelfClasses}>
                  {profile.top_rated.map((entry) => (
                    <div className={shelfItemClasses} key={entry.id}>
                      <MediaCard media={entry.media} rating={entry.rating} />
                    </div>
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
      <div className="mx-auto max-w-2xl rounded-2xl border border-white/5 bg-[#151921] p-6 sm:p-8">
        {user && (
          <form className="form-stack" onSubmit={submit}>
            <div className="form-row">
              <Field label="Имя">
                <Input
                  name="name"
                  defaultValue={user.name}
                  required
                  maxLength={100}
                  autoComplete="name"
                />
              </Field>
              <Field label="Логин">
                <Input
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
              <Input
                name="email"
                type="email"
                defaultValue={user.email}
                required
                autoComplete="email"
              />
            </Field>
            <Field label="Аватар" hint="JPEG, PNG или WebP, до 5 МБ">
              <Input
                name="avatar"
                type="file"
                accept="image/jpeg,image/png,image/webp"
              />
            </Field>
            {user.avatar_url && (
              <label className="check-label select-none">
                <Checkbox name="remove_avatar" />
                Удалить аватар
              </label>
            )}

            <div className="mt-8 border-t border-white/5 pt-8">
              <h2 className="mb-6! text-xl! font-bold! tracking-tight! text-white">
                Изменить пароль
              </h2>
              <div className="form-stack">
                <Field label="Текущий пароль">
                  <Input
                    name="current_password"
                    type="password"
                    autoComplete="current-password"
                  />
                </Field>
                <div className="form-row">
                  <Field label="Новый пароль">
                    <Input
                      name="password"
                      type="password"
                      minLength={8}
                      autoComplete="new-password"
                    />
                  </Field>
                  <Field label="Повтори новый пароль">
                    <Input
                      name="password_confirmation"
                      type="password"
                      minLength={8}
                      autoComplete="new-password"
                    />
                  </Field>
                </div>
              </div>
            </div>

            <div className="flex flex-col gap-2 sm:flex-row sm:pt-4">
              <Button type="submit" variant="primary" disabled={busy}>
                {busy ? "Сохраняем…" : "Сохранить профиль"}
              </Button>
              <Link href="/profile" className="button secondary min-h-12!">
                Назад
              </Link>
            </div>
          </form>
        )}
      </div>
    </RequireAuth>
  );
}