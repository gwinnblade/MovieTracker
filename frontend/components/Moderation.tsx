"use client";

import Link from "next/link";
import { useState } from "react";
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
  Modal,
  PageHeading,
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
        <Link className="button" href="/suggest">
          + Предложить фильм
        </Link>
      </PageHeading>
      <div className="tabs">
        {[
          ["", "Все заявки"],
          ["pending", "Ожидают"],
          ["approved", "Одобрены"],
          ["rejected", "Отклонены"],
        ].map(([value, title]) => (
          <button
            key={value}
            className={filter === value ? "active" : ""}
            onClick={() => setFilter(value)}
          >
            {title}
          </button>
        ))}
      </div>
      {data.isPending ? (
        <Loading />
      ) : data.error ? (
        <ErrorState error={data.error} retry={() => data.refetch()} />
      ) : items?.length ? (
        <div className="requests-list">
          {items.map((item) => (
            <article className="request-card panel" key={item.id}>
              <div className="request-top">
                {item.poster_key && (
                  <Artwork
                    className="request-poster"
                    src={item.poster_key}
                    alt={item.title_ru}
                  />
                )}
                <div>
                  <span
                    className={
                      "pill " +
                      (item.status === "approved"
                        ? "green"
                        : item.status === "rejected"
                          ? "red"
                          : "")
                    }
                  >
                    {statuses[item.status]}
                  </span>{" "}
                  <small>
                    #{item.id} ·{" "}
                    {item.action === "edit"
                      ? "Исправление карточки"
                      : "Новая карточка"}
                  </small>
                  <h2>{item.title_ru}</h2>
                  <small>
                    {item.title_en}
                    {item.release_year ? " · " + item.release_year : ""} ·{" "}
                    {item.type?.name_ru}
                  </small>
                  <p>
                    {isModerator && item.user
                      ? `Автор: ${item.user.name} (@${item.user.login}) · `
                      : ""}
                    {new Date(item.created_at).toLocaleDateString("ru-RU")}
                  </p>
                  <p className="request-description">{item.description_ru}</p>
                  <div className="genre-list">
                    {item.genres?.map((genre) => (
                      <span className="pill" key={genre.id}>
                        {genre.name_ru}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
              {item.status === "rejected" && (
                <div className="notice error">
                  Причина: {item.rejection_reason}
                </div>
              )}
              {item.status === "approved" && item.media_id && (
                <div className="form-actions">
                  <Link
                    className="button secondary small"
                    href={"/media/" + item.media_id}
                  >
                    Открыть карточку →
                  </Link>
                </div>
              )}
              {isModerator && item.status === "pending" && (
                <div className="form-actions">
                  <button
                    className="button"
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
                    Одобрить и опубликовать
                  </button>
                  <button
                    className="button danger"
                    disabled={busy}
                    onClick={() => {
                      setReason("");
                      setReject(item.id);
                    }}
                  >
                    Отклонить
                  </button>
                </div>
              )}
            </article>
          ))}
        </div>
      ) : (
        <Empty title="Заявок пока нет">
          <p>Предложи фильм или выбери другой статус.</p>
          <Link href="/suggest" className="button">
            Предложить фильм
          </Link>
        </Empty>
      )}
      {reject !== null && (
        <Modal title="Причина отклонения" onClose={() => setReject(null)}>
          <form
            className="form-stack"
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
              <textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                maxLength={1000}
                required
                placeholder="Объясни автору, что нужно изменить в карточке."
              />
            </Field>
            <div className="form-actions">
              <button className="button danger" disabled={busy}>
                Отклонить заявку
              </button>
              <button
                type="button"
                className="button secondary"
                onClick={() => setReject(null)}
              >
                Отмена
              </button>
            </div>
          </form>
        </Modal>
      )}
    </RequireAuth>
  );
}
