"use client";

import Link from "next/link";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { api, errorMessage } from "@/lib/api";
import { RequireAuth, useAuth } from "./Auth";
import {
  Empty,
  ErrorState,
  Field,
  Loading,
  MediaCard,
  Modal,
  PageHeading,
  Pagination,
} from "./UI";

export default function Entries() {
  const { user } = useAuth();
  const cache = useQueryClient();
  const [status, setStatus] = useState("");
  const [type, setType] = useState("");
  const [rated, setRated] = useState(false);
  const [sort, setSort] = useState("added");
  const [page, setPage] = useState(1);
  const [remove, setRemove] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const data = useQuery({
    queryKey: ["entries", user?.id, status, type, rated, sort, page],
    queryFn: () =>
      api.entries({
        status_id: status || undefined,
        type_id: type || undefined,
        rated,
        sort,
        page,
      }),
    enabled: !!user,
  });
  const statuses = useQuery({
    queryKey: ["statuses"],
    queryFn: () => api.references("statuses"),
  });
  const types = useQuery({
    queryKey: ["types"],
    queryFn: () => api.references("types"),
  });
  const changed = (fn: () => void) => {
    fn();
    setPage(1);
  };
  return (
    <RequireAuth>
      <PageHeading
        eyebrow="ТВОЯ БИБЛИОТЕКА"
        title="Мой список"
        description="То, что смотрел, смотришь и хочешь посмотреть."
      >
        <Link className="button" href="/catalog">
          + Найти фильм
        </Link>
      </PageHeading>
      <div className="filters">
        <Field label="Статус">
          <select
            value={status}
            onChange={(e) => changed(() => setStatus(e.target.value))}
          >
            <option value="">Все статусы</option>
            {statuses.data?.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name_ru}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Тип">
          <select
            value={type}
            onChange={(e) => changed(() => setType(e.target.value))}
          >
            <option value="">Все типы</option>
            {types.data?.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name_ru}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Сортировать">
          <select
            value={sort}
            onChange={(e) => changed(() => setSort(e.target.value))}
          >
            <option value="added">По добавлению</option>
            <option value="rating_desc">Сначала высокие оценки</option>
            <option value="rating_asc">Сначала низкие оценки</option>
          </select>
        </Field>
        <label className="check-label">
          <input
            type="checkbox"
            checked={rated}
            onChange={(e) => changed(() => setRated(e.target.checked))}
          />
          Только с оценкой
        </label>
      </div>
      {data.isPending ? (
        <Loading />
      ) : data.error ? (
        <ErrorState error={data.error} retry={() => data.refetch()} />
      ) : data.data?.data.length ? (
        <>
          <div className="entry-grid">
            {data.data.data.map((entry) => (
              <article className="entry-item" key={entry.id}>
                <MediaCard media={entry.media} rating={entry.rating} />
                <div className="entry-actions">
                  <span
                    className={
                      "pill " +
                      (entry.status?.code === "completed"
                        ? "green"
                        : entry.status?.code === "dropped"
                          ? "red"
                          : "")
                    }
                  >
                    {entry.status?.name_ru}
                  </span>
                  <button
                    className="text-button delete-link"
                    onClick={() => setRemove(entry.id)}
                  >
                    Удалить
                  </button>
                </div>
                {entry.note && (
                  <p className="entry-note" title={entry.note}>
                    {entry.note}
                  </p>
                )}
                {!!entry.episodes_watched && (
                  <small>{entry.episodes_watched} серий просмотрено</small>
                )}
              </article>
            ))}
          </div>
          <Pagination
            page={page}
            last={data.data.last_page}
            total={data.data.total}
            onChange={setPage}
          />
        </>
      ) : (
        <Empty title="Здесь будут твои истории">
          <p>Сохрани первый фильм или измени фильтры.</p>
          <Link href="/catalog" className="button">
            Открыть кино
          </Link>
        </Empty>
      )}
      {remove !== null && (
        <Modal
          title="Удалить из личного списка?"
          onClose={() => setRemove(null)}
        >
          <p>
            Оценка и общая заметка к фильму будут удалены. Коллекции и заметки к
            сериям сохранятся.
          </p>
          <div className="form-actions">
            <button
              className="button danger"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  await api.deleteEntry(remove);
                  setRemove(null);
                  await cache.invalidateQueries({ queryKey: ["entries"] });
                  await cache.invalidateQueries({ queryKey: ["profile"] });
                  await cache.invalidateQueries({ queryKey: ["tracking"] });
                  toast.success("Запись удалена");
                } catch (error) {
                  toast.error(errorMessage(error));
                } finally {
                  setBusy(false);
                }
              }}
            >
              Удалить
            </button>
            <button
              className="button secondary"
              onClick={() => setRemove(null)}
            >
              Отмена
            </button>
          </div>
        </Modal>
      )}
    </RequireAuth>
  );
}
