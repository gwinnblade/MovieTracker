"use client";
import Link from "next/link";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { api, errorMessage } from "@/lib/api";
import { RequireAuth, useAuth } from "./Auth";
import {
  Button,
  Checkbox,
  Empty,
  ErrorState,
  Field,
  Loading,
  MediaCard,
  Modal,
  Pagination,
  Select,
} from "./UI";

const dangerButtonClasses =
  "border-2 border-[var(--red)] bg-[var(--red)]/10 text-[var(--red)] shadow-[4px_4px_0px_0px_var(--red)] enabled:hover:-translate-x-0.5 enabled:hover:-translate-y-0.5 enabled:hover:shadow-[6px_6px_0px_0px_var(--red)]";

// Keep overrides for the shared MediaCard local to this list.
const entryCardClasses = [
  "group flex h-full min-w-0 flex-col border-2 border-white/10 bg-[var(--panel)]",
  "shadow-[8px_8px_0px_0px_rgba(255,255,255,0.05)] transition-all duration-150",
  "hover:-translate-x-0.5 hover:-translate-y-0.5 hover:border-[var(--accent)] hover:shadow-[10px_10px_0px_0px_var(--accent)]",
  "focus-within:border-[var(--accent)] motion-reduce:hover:translate-x-0 motion-reduce:hover:translate-y-0 motion-reduce:transition-none",
  "[&_.media-card]:!rounded-none [&_.media-card]:!border-0 [&_.media-card]:!bg-transparent",
  "[&_.media-card]:!p-0 [&_.media-card]:!shadow-none [&_.media-card]:!transform-none",
  "[&_.poster-wrap]:overflow-hidden [&_.poster-wrap]:!rounded-none",
  "[&_.poster-wrap::after]:!bg-[linear-gradient(to_top,rgba(11,14,20,0.92),transparent_70%)]",
  "[&_.poster-wrap::after]:!opacity-0 [&_.poster-wrap::after]:!duration-150",
  "hover:[&_.poster-wrap::after]:!opacity-100 focus-within:[&_.poster-wrap::after]:!opacity-100",
  "[&_.media-card_h3]:!mx-3 [&_.media-card_h3]:!mt-3 [&_.media-card_h3]:!mb-0",
  "[&_.media-card_h3]:!h-10 [&_.media-card_h3]:!min-h-0 [&_.media-card_h3]:!line-clamp-2",
  "[&_.media-card_h3]:!text-sm [&_.media-card_h3]:!font-black [&_.media-card_h3]:!uppercase [&_.media-card_h3]:!tracking-tight [&_.media-card_h3]:!text-[var(--text)]",
  "[&_.media-meta]:!mx-3 [&_.media-meta]:!mt-1 [&_.media-meta]:!mb-3 [&_.media-meta]:!h-5 [&_.media-meta]:!gap-2",
  "[&_.media-meta]:!text-[10px] [&_.media-meta]:!font-mono [&_.media-meta]:!uppercase [&_.media-meta]:!tracking-widest [&_.media-meta]:!text-[var(--subtle)]",
  "[&_.media-meta_p]:!min-w-0 [&_.media-meta_p]:!truncate [&_.media-meta_p]:!text-[10px] [&_.media-meta_p]:!text-[var(--subtle)]",
  "[&_.media-type]:shrink-0 [&_.media-type]:!text-[10px] [&_.media-type]:!font-mono [&_.media-type]:!uppercase [&_.media-type]:!tracking-widest [&_.media-type]:!text-[var(--subtle)]",
].join(" ");

// Inline Lucide SVG paths; no additional dependency is needed.
const iconPaths = {
  plus: ["M5 12h14", "M12 5v14"],
  trash: [
    "M3 6h18",
    "M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6",
    "M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2",
  ],
  check: ["M20 6 9 17l-5-5"],
};

function ListIcon({
  name,
  className = "size-4 shrink-0",
}: {
  name: keyof typeof iconPaths;
  className?: string;
}) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
      focusable="false"
    >
      {iconPaths[name].map((path) => (
        <path key={path} d={path} />
      ))}
    </svg>
  );
}

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
        rated: rated ? 1 : 0,
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
      <header className="mb-6 flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <span className="mb-3 inline-block border-2 border-[var(--accent)] bg-[var(--accent)] px-3 py-1 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)]">
            [ Твоя библиотека ]
          </span>
          <h1 className="text-4xl font-black uppercase leading-[1.05] tracking-tighter text-[var(--text)] sm:text-5xl">
            Мой список
          </h1>
          <p className="mt-3 max-w-md text-sm text-[var(--muted)]">
            То, что смотрел, смотришь и хочешь посмотреть.
          </p>
        </div>
        <Link
          className="group inline-flex items-center gap-2 border-2 border-[var(--accent)] bg-[var(--accent)] px-5 py-3 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)] shadow-[4px_4px_0px_0px_var(--text)] transition-all hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[6px_6px_0px_0px_var(--text)] active:translate-x-0 active:translate-y-0 active:shadow-none"
          href="/catalog"
        >
          <ListIcon name="plus" className="size-4 shrink-0" />
          Найти фильм
        </Link>
      </header>

      <div className="relative mb-8 grid grid-cols-1 items-end gap-4 border-2 border-white/10 bg-[var(--panel)] p-5 shadow-[8px_8px_0px_0px_var(--accent)] sm:grid-cols-2 lg:grid-cols-[1fr_1fr_1.25fr_auto]">
        {/* Solid accent rule — ticket stub edge */}
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-1 bg-[var(--accent)]"
          aria-hidden="true"
        />

        <Field label="Статус">
          <Select
            value={status}
            onChange={(e) => changed(() => setStatus(e.target.value))}
          >
            <option value="">Все статусы</option>
            {statuses.data?.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name_ru}
              </option>
            ))}
          </Select>
        </Field>

        <Field label="Тип">
          <Select
            value={type}
            onChange={(e) => changed(() => setType(e.target.value))}
          >
            <option value="">Все типы</option>
            {types.data?.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name_ru}
              </option>
            ))}
          </Select>
        </Field>

        <Field label="Сортировать">
          <Select
            value={sort}
            onChange={(e) => changed(() => setSort(e.target.value))}
          >
            <option value="added">По добавлению</option>
            <option value="rating_desc">Сначала высокие оценки</option>
            <option value="rating_asc">Сначала низкие оценки</option>
          </Select>
        </Field>

        <label className="flex h-12 cursor-pointer items-center gap-3 border-2 border-white/10 bg-[var(--bg)] px-3 font-mono text-[11px] uppercase tracking-widest text-[var(--muted)] transition-colors hover:border-white/30 hover:text-[var(--text)]">
          <Checkbox
            checked={rated}
            onChange={(e) => changed(() => setRated(e.target.checked))}
          />
          <span className="whitespace-nowrap">Только с оценкой</span>
        </label>
      </div>

      {data.isPending ? (
        <Loading />
      ) : data.error ? (
        <ErrorState error={data.error} retry={() => data.refetch()} />
      ) : data.data?.data.length ? (
        <>
          <div className="grid auto-rows-fr grid-cols-2 items-stretch gap-5 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
            {data.data.data.map((entry) => (
              <article className={entryCardClasses} key={entry.id}>
                <MediaCard media={entry.media} rating={entry.rating} />
                <div className="flex min-h-[140px] flex-1 flex-col gap-2 border-t-2 border-white/10 bg-[var(--bg)] p-3">
                  <div className="flex min-h-8 shrink-0 items-center justify-between gap-2">
                    <span
                      className={`min-w-0 max-w-[60%] truncate border-2 px-2 py-1 font-mono text-[10px] font-black uppercase leading-none tracking-widest ${
                        entry.status?.code === "watching" ||
                        entry.status?.name_ru === "Смотрю"
                          ? "border-[var(--bg)] bg-[var(--accent)] text-[var(--bg)] shadow-[2px_2px_0px_0px_var(--text)]"
                          : "border-white/20 bg-white/5 text-[var(--muted)]"
                      }`}
                      title={entry.status?.name_ru}
                    >
                      {entry.status?.name_ru}
                    </span>
                    <button
                      type="button"
                      className="inline-flex size-8 shrink-0 items-center justify-center border-2 border-transparent text-[var(--subtle)] transition-all duration-150 hover:border-[var(--red)] hover:bg-[var(--red)]/10 hover:text-[var(--red)] hover:shadow-[3px_3px_0px_0px_var(--red)] active:translate-x-0.5 active:translate-y-0.5 active:shadow-none focus-visible:outline-2 focus-visible:outline-[var(--accent)] focus-visible:outline-offset-2 motion-reduce:transition-none"
                      aria-label={`Удалить «${entry.media.title_ru}» из списка`}
                      title="Удалить"
                      onClick={() => setRemove(entry.id)}
                    >
                      <ListIcon name="trash" />
                    </button>
                  </div>
                  {!!entry.episodes_watched && (
                    <span
                      className="inline-flex max-w-full shrink-0 items-center gap-1.5 self-start border-2 border-white/10 bg-white/5 px-2 py-0.5 font-mono text-[10px] uppercase leading-none tracking-widest text-[var(--muted)]"
                      title={`${entry.episodes_watched} серий просмотрено`}
                    >
                      <ListIcon
                        name="check"
                        className="size-3 shrink-0 text-[var(--accent)]"
                      />
                      <span className="truncate">
                        {entry.episodes_watched} серий
                      </span>
                    </span>
                  )}
                  {entry.note && (
                    <div className="mt-auto pt-2">
                      <blockquote
                        className="flex min-w-0 flex-col justify-center border-l-4 border-[var(--accent)] bg-[var(--panel)] p-3 text-sm leading-5 text-[var(--muted)]"
                        title={entry.note}
                      >
                        <p className="line-clamp-2 [overflow-wrap:anywhere]">
                          {entry.note}
                        </p>
                      </blockquote>
                    </div>
                  )}
                </div>
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
          <Link
            href="/catalog"
            className="inline-flex items-center gap-2 border-2 border-[var(--accent)] bg-[var(--accent)] px-5 py-3 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)] shadow-[4px_4px_0px_0px_var(--text)] transition-all hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[6px_6px_0px_0px_var(--text)] active:translate-x-0 active:translate-y-0 active:shadow-none"
          >
            Открыть кино
          </Link>
        </Empty>
      )}

      {remove !== null && (
        <Modal
          title="Удалить из личного списка?"
          onClose={() => setRemove(null)}
        >
          <p className="leading-relaxed text-[var(--muted)]">
            Оценка и общая заметка к фильму будут удалены. Коллекции и заметки
            к сериям сохранятся.
          </p>
          <div className="form-actions">
            <Button
              variant="secondary"
              className={dangerButtonClasses}
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
            </Button>
            <Button variant="secondary" onClick={() => setRemove(null)}>
              Отмена
            </Button>
          </div>
        </Modal>
      )}
    </RequireAuth>
  );
}