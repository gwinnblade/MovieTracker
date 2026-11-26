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
        eyebrow={isModerator ? "КАТАЛОГ СООБЩЕСТВА" : "ТВОЙ ВКЛАД В КАТАЛОГ"}
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

      <div className="mb-8 inline-flex w-full flex-wrap gap-1 overflow-x-auto rounded-xl border border-white/5 bg-[#151921]/80 p-1 backdrop-blur-md [&::-webkit-scrollbar]:hidden sm:w-auto">
        {[
          { value: "", title: "Все заявки", Icon: Squares2X2Icon },
          { value: "pending", title: "Ожидают", Icon: ClockIcon },
          { value: "approved", title: "Одобрены", Icon: CheckCircleIcon },
          { value: "rejected", title: "Отклонены", Icon: XCircleIcon },
        ].map(({ value, title, Icon }) => (
          <button
            key={value}
            className={`inline-flex items-center gap-2 whitespace-nowrap rounded-lg border px-4 py-2 text-sm font-medium transition-all duration-300 ${
              filter === value
                ? "border-gold/20 bg-gold/10 text-gold"
                : "border-transparent text-zinc-400 hover:bg-white/[0.03] hover:text-white"
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
              className="rounded-2xl border border-white/5 bg-[#151921] p-6 transition-all duration-300 hover:border-gold/20 hover:shadow-[0_0_30px_rgba(229,169,61,0.08)]"
              key={item.id}
            >
              <div className="flex flex-col gap-5 sm:flex-row">
                {item.poster_key && (
                  <Artwork
                    className="w-[110px] shrink-0 rounded-xl border border-white/10 shadow-[0_10px_30px_rgba(0,0,0,0.5)]"
                    src={item.poster_key}
                    alt={item.title_ru}
                  />
                )}
                <div className="min-w-0 flex-1">
                  <span
                    className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium ${
                      item.status === "approved"
                        ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
                        : item.status === "rejected"
                          ? "border-red-500/20 bg-red-500/10 text-red-400"
                          : "border-amber-500/20 bg-amber-500/10 text-amber-400"
                    }`}
                  >
                    <span className="size-1.5 rounded-full bg-current" />
                    {statuses[item.status]}
                  </span>
                  <h2 className="mt-3 text-2xl font-bold tracking-tight text-white">
                    {item.title_ru}
                  </h2>
                  <p className="mt-1 flex flex-wrap items-center gap-2 text-xs text-zinc-500">
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
                  <p className="mt-3 line-clamp-3 text-sm leading-relaxed text-zinc-400">
                    {item.description_ru}
                  </p>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {item.genres?.map((genre) => (
                      <span
                        className="inline-flex items-center rounded-sm border border-gold/20 bg-gold/5 px-2.5 py-1 text-xs font-medium text-gold/90"
                        key={genre.id}
                      >
                        {genre.name_ru}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {item.status === "rejected" && (
                <div className="mt-4 rounded-xl border border-red-500/20 bg-red-500/[0.03] p-4 text-sm text-red-300">
                  <span className="font-semibold">Причина: </span>
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