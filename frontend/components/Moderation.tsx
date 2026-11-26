"use client";

import {
  ArrowRightIcon,
  CheckCircleIcon,
  CheckIcon,
  ClockIcon,
  Squares2X2Icon,
  XCircleIcon,
  XMarkIcon,
} from "@heroicons/react/24/outline";

import Link from "next/link";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { api, errorMessage } from "@/lib/api";
import { RequireAuth, useAuth } from "./Auth";
import {
  Artwork,
  Button,
  Empty,
  ErrorState,
  Field,
  Loading,
  Modal,
  PageHeading,
  Textarea,
} from "./UI";

const statuses = {
  pending: "Ожидает проверки",
  approved: "Одобрено",
  rejected: "Отклонено",
};

export default function Moderation() {
  const { user } = useAuth();
  const cache = useQueryClient();
  const isModerator = !!user && ["admin", "moderator"].includes(user.role);
  const [filter, setFilter] = useState("");
  const [reject, setReject] = useState<number | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const data = useQuery({
    queryKey: ["requests", user?.id],
    queryFn: () => api.requests(),
    enabled: !!user,
  });
  const refresh = async () => {
    await Promise.all([
      cache.invalidateQueries({ queryKey: ["requests"] }),
      cache.invalidateQueries({ queryKey: ["browse"] }),
      cache.invalidateQueries({ queryKey: ["detail"] }),
      cache.invalidateQueries({ queryKey: ["summary"] }),
    ]);
  };
  const items = data.data?.filter((item) => !filter || item.status === filter);

  return (
    <RequireAuth>
      <PageHeading
        eyebrow={isModerator ? "[ КАТАЛОГ СООБЩЕСТВА ]" : "[ ТВОЙ ВКЛАД В КАТАЛОГ ]"}
        title={isModerator ? "Модерация" : "Мои заявки"}
        description={
          isModerator
            ? "Проверь предложенные фильмы и исправления перед публикацией."
            : "Следи за проверкой своих фильмов и предложенных исправлений."
        }
      >
        <Link href="/suggest">
          <Button variant="primary">+ Предложить фильм</Button>
        </Link>
      </PageHeading>

      <div className="mb-8 inline-flex w-full flex-wrap gap-0 border-2 border-white/10 bg-[var(--panel)] sm:w-auto">
        {[
          { value: "", title: "Все заявки", Icon: Squares2X2Icon },
          { value: "pending", title: "Ожидают", Icon: ClockIcon },
          { value: "approved", title: "Одобрены", Icon: CheckCircleIcon },
          { value: "rejected", title: "Отклонены", Icon: XCircleIcon },
        ].map(({ value, title, Icon }) => (
          <button
            key={value}
            className={`inline-flex items-center gap-2 whitespace-nowrap border-r-2 border-white/10 px-5 py-3 font-mono text-[11px] font-black uppercase tracking-widest transition-[background-color,color] duration-150 last:border-r-0 ${
              filter === value
                ? "border-r-2 border-white/10 bg-[var(--accent)] text-[var(--bg)] shadow-[3px_3px_0px_0px_var(--text)]"
                : "border-r-2 border-white/10 bg-transparent text-[var(--muted)] hover:bg-white/5 hover:text-[var(--text)]"
            }`}
            onClick={() => setFilter(value)}
          >
            <Icon className="size-4" aria-hidden="true" />
            {title}
          </button>
        ))}
      </div>

      {data.isPending ? (
        <Loading />
      ) : data.error ? (
        <ErrorState error={data.error} retry={() => data.refetch()} />
      ) : items?.length ? (
        <div className="flex flex-col gap-5">
          {items.map((item) => (
            <article
              className="border-2 border-white/10 bg-[var(--panel)] p-6 shadow-[8px_8px_0px_0px_rgba(255,255,255,0.05)] transition-all duration-150 hover:-translate-x-0.5 hover:-translate-y-0.5 hover:border-[var(--accent)] hover:shadow-[10px_10px_0px_0px_var(--accent)]"
              key={item.id}
            >
              <div className="flex flex-col gap-5 sm:flex-row">
                {item.poster_key && (
                  <Artwork
                    className="w-[110px] shrink-0 border-2 border-white/20 shadow-[6px_6px_0px_0px_var(--accent)]"
                    src={item.poster_key}
                    alt={item.title_ru}
                  />
                )}
                <div className="min-w-0 flex-1">
                  <span
                    className={`inline-flex items-center gap-1.5 border-2 px-3 py-1 font-mono text-[10px] font-black uppercase tracking-widest ${
                      item.status === "approved"
                        ? "border-[var(--bg)] bg-[var(--green)] text-[var(--bg)]"
                        : item.status === "rejected"
                          ? "border-[var(--bg)] bg-[var(--red)] text-[var(--bg)]"
                          : "border-[var(--bg)] bg-[var(--accent)] text-[var(--bg)]"
                    }`}
                  >
                    <span className="size-1.5 bg-current" aria-hidden="true" />
                    {statuses[item.status]}
                  </span>
                  <h2 className="mt-3 text-2xl font-black uppercase tracking-tight text-[var(--text)]">
                    {item.title_ru}
                  </h2>
                  <p className="mt-1 flex flex-wrap items-center gap-2 font-mono text-[11px] uppercase tracking-widest text-[var(--subtle)]">
                    <span>#{item.id}</span>
                    <span>
                      ·{" "}
                      {item.action === "edit"
                        ? "Исправление карточки"
                        : "Новая карточка"}
                    </span>
                    {item.title_en && <span>· {item.title_en}</span>}
                    {item.release_year && <span>· {item.release_year}</span>}
                    {item.type?.name_ru && <span>· {item.type.name_ru}</span>}
                    <span>
                      ·{" "}
                      {new Date(item.created_at).toLocaleDateString("ru-RU")}
                    </span>
                    {isModerator && item.user && (
                      <span>· Автор: {item.user.name}</span>
                    )}
                  </p>
                  <p className="mt-3 line-clamp-3 text-sm leading-relaxed text-[var(--muted)]">
                    {item.description_ru}
                  </p>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {item.genres?.map((genre) => (
                      <span
                        className="inline-flex items-center border-2 border-[var(--accent)] bg-[var(--accent)] px-2.5 py-1 font-mono text-[10px] font-black uppercase tracking-widest text-[var(--bg)]"
                        key={genre.id}
                      >
                        {genre.name_ru}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {item.status === "rejected" && (
                <div className="mt-4 border-2 border-[var(--red)] bg-[var(--red)]/10 p-4 text-sm text-[var(--red)] shadow-[4px_4px_0px_0px_var(--red)]">
                  <span className="font-black uppercase tracking-wider">Причина: </span>
                  {item.rejection_reason}
                </div>
              )}

              {item.status === "approved" && item.media_id && (
                <div className="mt-5 flex flex-col gap-2 sm:flex-row">
                  <Link href={"/media/" + item.media_id}>
                    <Button variant="secondary">
                      Открыть карточку{" "}
                      <ArrowRightIcon className="size-4" aria-hidden="true" />
                    </Button>
                  </Link>
                </div>
              )}

              {isModerator && item.status === "pending" && (
                <div className="mt-5 flex flex-col gap-2 sm:flex-row">
                  <Button
                    type="button"
                    variant="primary"
                    disabled={busy}
                    onClick={async () => {
                      setBusy(true);
                      try {
                        await api.approve(item.id);
                        await refresh();
                        toast.success("Карточка опубликована в каталоге");
                      } catch (error) {
                        toast.error(errorMessage(error));
                      } finally {
                        setBusy(false);
                      }
                    }}
                  >
                    <CheckIcon className="size-4" aria-hidden="true" />
                    Одобрить и опубликовать
                  </Button>
                  <Button
                    type="button"
                    variant="danger"
                    disabled={busy}
                    onClick={() => {
                      setReason("");
                      setReject(item.id);
                    }}
                  >
                    <XMarkIcon className="size-4" aria-hidden="true" />
                    Отклонить
                  </Button>
                </div>
              )}
            </article>
          ))}
        </div>
      ) : (
        <Empty title="Заявок пока нет">
          <p>Предложи фильм или выбери другой статус.</p>
          <Link href="/suggest">
            <Button variant="primary">Предложить фильм</Button>
          </Link>
        </Empty>
      )}

      {reject !== null && (
        <Modal title="Причина отклонения" onClose={() => setReject(null)}>
          <form
            className="space-y-4"
            onSubmit={async (event) => {
              event.preventDefault();
              setBusy(true);
              try {
                await api.reject(reject, reason);
                await refresh();
                setReject(null);
                toast.success("Заявка отклонена");
              } catch (error) {
                toast.error(errorMessage(error));
              } finally {
                setBusy(false);
              }
            }}
          >
            <Field label="Что нужно исправить">
              <Textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                maxLength={1000}
                required
                placeholder="Объясни автору, что нужно изменить в карточке."
              />
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button type="submit" variant="danger" disabled={busy}>
                Отклонить заявку
              </Button>
              <Button
                type="button"
                variant="secondary"
                onClick={() => setReject(null)}
              >
                Отмена
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </RequireAuth>
  );
}