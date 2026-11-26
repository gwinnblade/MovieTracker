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
  "-mx-4 flex snap-x snap-mandatory gap-5 overflow-x-auto px-4 pt-4 pb-3 [&::-webkit-scrollbar]:hidden [scrollbar-width:none]";

const shelfItemClasses = "w-[160px] shrink-0 snap-start sm:w-[180px]";

const shelfLinkClasses =
  "group inline-flex shrink-0 items-center gap-2 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--muted)] transition-colors duration-150 hover:text-[var(--accent)]";

const miniPillClasses =
  "inline-flex items-center border-2 border-white/20 bg-white/5 px-3 py-1 font-mono text-[10px] font-black uppercase tracking-widest text-[var(--muted)]";

const stampClasses =
  "inline-block border-2 border-[var(--accent)] bg-[var(--accent)] px-3 py-1 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)]";

const sectionTitleClasses =
  "text-2xl font-black uppercase leading-none tracking-tighter text-[var(--text)] sm:text-3xl";

const actionLinkClasses =
  "inline-flex min-h-11 items-center justify-center gap-2 border-2 border-white/20 bg-transparent px-4 py-2.5 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--text)] shadow-[4px_4px_0px_0px_rgba(255,255,255,0.08)] transition-[transform,box-shadow,border-color] duration-150 ease-out hover:-translate-x-0.5 hover:-translate-y-0.5 hover:border-white/40 hover:shadow-[6px_6px_0px_0px_rgba(255,255,255,0.14)] active:translate-x-0 active:translate-y-0 active:shadow-none";

const primaryLinkClasses =
  "inline-flex min-h-11 items-center justify-center gap-2 border-2 border-[var(--accent)] bg-[var(--accent)] px-4 py-2.5 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)] shadow-[4px_4px_0px_0px_var(--text)] transition-[transform,box-shadow] duration-150 ease-out hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[6px_6px_0px_0px_var(--text)] active:translate-x-0 active:translate-y-0 active:shadow-none";

const barTrackClasses =
  "h-3 overflow-hidden border-2 border-white/15 bg-[var(--bg)]";

const barFillClasses =
  "block h-full bg-[var(--accent)] transition-[width] duration-150 ease-out";

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
          eyebrow="[ ТВОЯ СТАТИСТИКА ]"
          title="История в цифрах"
          description="Каждая оценка и просмотренная серия — часть твоего дневника кино."
        />
      ) : (
        user && (
          <div className="relative flex flex-wrap items-center gap-6 border-2 border-white/10 bg-[var(--panel)] p-6 shadow-[10px_10px_0px_0px_var(--accent)] sm:p-8">
            {/* Solid accent rule — ticket stub edge */}
            <div
              className="pointer-events-none absolute inset-x-0 top-0 h-1 bg-[var(--accent)]"
              aria-hidden="true"
            />
            <Artwork
              src={user.avatar_url}
              alt={user.name}
              className="avatar size-24! shrink-0 rounded-none! border-2! border-white/20! shadow-[6px_6px_0px_0px_var(--accent)]!"
            />
            <div className="min-w-0 flex-1">
              <span className={stampClasses}>[ Твой профиль ]</span>
              <h1 className="mt-4 text-3xl font-black uppercase leading-[1.05] tracking-tighter text-[var(--text)] sm:text-4xl">
                {user.name}
              </h1>
              <p className="mt-2 font-mono text-[11px] uppercase tracking-widest text-[var(--subtle)]">
                @{user.login} · {user.email}
              </p>
            </div>
            <div className="profile-actions">
              <Link className={actionLinkClasses} href="/profile/edit">
                <PencilSquareIcon className="size-4" aria-hidden="true" />
                Редактировать
              </Link>
              <Link className={actionLinkClasses} href="/suggest">
                <PlusIcon className="size-4" aria-hidden="true" />
                Предложить фильм
              </Link>
              <Link className={actionLinkClasses} href="/moderation">
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
            <div className="my-8 grid grid-cols-2 gap-5 lg:grid-cols-4">
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
                  className="relative border-2 border-white/10 bg-[var(--panel)] p-5 shadow-[6px_6px_0px_0px_rgba(255,255,255,0.06)] transition-[transform,box-shadow,border-color] duration-150 ease-out hover:-translate-x-0.5 hover:-translate-y-0.5 hover:border-[var(--accent)] hover:shadow-[8px_8px_0px_0px_var(--accent)]"
                >
                  <span className="absolute right-4 top-4 grid size-7 place-items-center border-2 border-white/15 text-[var(--subtle)]">
                    <Icon className="size-3.5" aria-hidden="true" />
                  </span>
                  <strong className="block pr-9 text-4xl font-black leading-none tracking-tighter text-[var(--text)] tabular-nums">
                    {value}
                  </strong>
                  <span className="mt-3 block border-t-2 border-white/10 pt-3 font-mono text-[10px] font-black uppercase tracking-widest text-[var(--muted)]">
                    {name}
                  </span>
                </div>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-2">
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

            <div className="my-8 grid gap-6 md:grid-cols-2">
              <section className="border-2 border-white/10 bg-[var(--panel)] p-6 shadow-[8px_8px_0px_0px_rgba(255,255,255,0.06)]">
                <h2 className="mb-6 border-b-2 border-white/10 pb-4 text-xl font-black uppercase tracking-tight text-[var(--text)]">
                  Статусы просмотра
                </h2>
                {profile.stats.statuses.length ? (
                  profile.stats.statuses.map((status) => (
                    <div
                      className="mb-4 grid grid-cols-[110px_1fr_40px] items-center gap-3"
                      key={status.name}
                    >
                      <span className="truncate font-mono text-[10px] font-black uppercase tracking-widest text-[var(--muted)]">
                        {status.name}
                      </span>
                      <div className={barTrackClasses}>
                        <span
                          className={barFillClasses}
                          style={{
                            width: `${(status.count / Math.max(1, profile.stats.total)) * 100}%`,
                          }}
                        />
                      </div>
                      <b className="text-right font-mono text-sm font-black text-[var(--text)] tabular-nums">
                        {status.count}
                      </b>
                    </div>
                  ))
                ) : (
                  <p className="text-sm leading-relaxed text-[var(--muted)]">
                    Добавь первые фильмы в свой список.
                  </p>
                )}
              </section>
              <section className="border-2 border-white/10 bg-[var(--panel)] p-6 shadow-[8px_8px_0px_0px_rgba(255,255,255,0.06)]">
                <h2 className="mb-6 border-b-2 border-white/10 pb-4 text-xl font-black uppercase tracking-tight text-[var(--text)]">
                  Любимые жанры
                </h2>
                {profile.top_genres.length ? (
                  profile.top_genres.map((genre) => (
                    <div
                      className="mb-4 grid grid-cols-[110px_1fr_40px] items-center gap-3"
                      key={genre.name_ru}
                    >
                      <span className="truncate font-mono text-[10px] font-black uppercase tracking-widest text-[var(--muted)]">
                        {genre.name_ru}
                      </span>
                      <div className={barTrackClasses}>
                        <span
                          className={barFillClasses}
                          style={{
                            width: `${(genre.count / Math.max(...profile.top_genres.map((g) => g.count))) * 100}%`,
                          }}
                        />
                      </div>
                      <b className="text-right font-mono text-sm font-black text-[var(--text)] tabular-nums">
                        {genre.count}
                      </b>
                    </div>
                  ))
                ) : (
                  <p className="text-sm leading-relaxed text-[var(--muted)]">
                    Жанры появятся после загрузки карточек твоих фильмов.
                  </p>
                )}
              </section>
            </div>

            {profile.recent_activity.length ? (
              <section className="section">
                <div className="mb-2 flex items-baseline justify-between gap-4 border-b-2 border-white/10 pb-4">
                  <h2 className={sectionTitleClasses}>Недавно добавлено</h2>
                  <Link href="/entries" className={shelfLinkClasses}>
                    Весь список
                    <ArrowRightIcon className="size-4" aria-hidden="true" />
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
                <Link href="/catalog" className={primaryLinkClasses}>
                  Найти фильм
                </Link>
              </Empty>
            )}

            {!!profile.top_rated.length && (
              <section className="section">
                <div className="mb-2 flex items-baseline justify-between gap-4 border-b-2 border-white/10 pb-4">
                  <h2 className={sectionTitleClasses}>Твои высокие оценки</h2>
                  <Link href="/entries" className={shelfLinkClasses}>
                    Мой список
                    <ArrowRightIcon className="size-4" aria-hidden="true" />
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
      <PageHeading eyebrow="[ НАСТРОЙКИ АККАУНТА ]" title="Твой профиль" />
      <div className="relative mx-auto max-w-2xl border-2 border-white/10 bg-[var(--panel)] p-6 shadow-[10px_10px_0px_0px_var(--accent)] sm:p-8">
        {/* Solid accent rule — ticket stub edge */}
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-1 bg-[var(--accent)]"
          aria-hidden="true"
        />
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

            <div className="mt-8 border-t-2 border-white/10 pt-8">
              <span className={stampClasses}>[ Смена пароля ]</span>
              <div className="form-stack mt-6">
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

            <div className="flex flex-col gap-3 sm:flex-row sm:pt-4">
              <Button type="submit" variant="primary" disabled={busy}>
                {busy ? "Сохраняем…" : "Сохранить профиль"}
              </Button>
              <Link href="/profile" className={actionLinkClasses}>
                Назад
              </Link>
            </div>
          </form>
        )}
      </div>
    </RequireAuth>
  );
}