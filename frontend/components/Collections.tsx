"use client";

import {
  ArrowUpRightIcon,
  PlusIcon,
  Squares2X2Icon,
  TrashIcon,
} from "@heroicons/react/24/outline";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { api, errorMessage } from "@/lib/api";
import type { Collection } from "@/lib/types";
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
  Modal,
  PageHeading,
  Textarea,
} from "./UI";

const dangerButton =
  "border-red-500/40! bg-red-500/15! text-red-200! focus-visible:ring-red-500/40! enabled:hover:border-red-500/60! enabled:hover:bg-red-500/25! enabled:hover:text-red-100!";

const compactButton = "min-h-9! px-3.5! py-2! text-xs!";

export default function Collections() {
  const { user } = useAuth();
  const cache = useQueryClient();
  const [create, setCreate] = useState(false);

  const data = useQuery({
    queryKey: ["collections", user?.id],
    queryFn: api.collections,
    enabled: !!user,
  });

  return (
    <RequireAuth>
      <PageHeading
        eyebrow="ТВОИ ПОДБОРКИ"
        title="Коллекции"
        description="Вечер с друзьями, любимый режиссёр или фильмы на потом. Собирай кино по своему настроению."
      >
        <Button
          variant="primary"
          className="group"
          onClick={() => setCreate(true)}
        >
          <PlusIcon
            className="ui-icon transition-transform duration-300 group-hover:rotate-90"
            aria-hidden="true"
          />{" "}
          Создать коллекцию
        </Button>
      </PageHeading>

      {data.isPending ? (
        <Loading />
      ) : data.error ? (
        <ErrorState error={data.error} retry={() => data.refetch()} />
      ) : data.data.length ? (
        <div className="collections-grid">
          {data.data.map((list) => (
            <Link
              className="collection-card panel group flex h-full flex-col transform-none! rounded-2xl! transition-all! duration-300! hover:-translate-y-1 hover:shadow-[0_0_20px_rgba(229,169,61,0.15)]!"
              key={list.id}
              href={"/collections/" + list.id}
            >
              {list.cover_url ? (
                <Artwork
                  className="collection-cover rounded-xl!"
                  src={list.cover_url}
                  alt={list.name}
                />
              ) : (
                <div className="collection-cover artwork-placeholder h-auto! rounded-xl!">
                  <Squares2X2Icon className="ui-icon" aria-hidden="true" />{" "}
                  <span>Твоя подборка кино</span>
                </div>
              )}
              <h3 className="line-clamp-1">{list.name}</h3>
              <p>{list.description || "Истории, которые стоит сохранить."}</p>
              <div className="row mt-auto border-t border-white/5 pt-3">
                <small>{list.media_count} записей</small>
                <span
                  className={
                    list.is_public
                      ? "inline-flex items-center rounded-md border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400"
                      : "inline-flex items-center rounded-md border border-white/10 bg-white/5 px-2 py-0.5 text-[10px] font-semibold text-zinc-400"
                  }
                >
                  {list.is_public ? "Публичная" : "Личная"}
                </span>
              </div>
            </Link>
          ))}
        </div>
      ) : (
        <Empty title="Собери первую коллекцию">
          <p>Добавляй фильмы и сериалы с любой карточки.</p>
          <Button variant="primary" onClick={() => setCreate(true)}>
            Создать коллекцию
          </Button>
        </Empty>
      )}

      {create && (
        <Modal title="Новая коллекция" onClose={() => setCreate(false)}>
          <CollectionForm
            onSaved={async () => {
              setCreate(false);
              await cache.invalidateQueries({ queryKey: ["collections"] });
              await cache.invalidateQueries({ queryKey: ["profile"] });
            }}
            onCancel={() => setCreate(false)}
          />
        </Modal>
      )}
    </RequireAuth>
  );
}

function CollectionForm({
  list,
  onSaved,
  onCancel,
}: {
  list?: Collection;
  onSaved: () => Promise<void>;
  onCancel: () => void;
}) {
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    form.set("is_public", form.get("is_public") ? "1" : "0");
    const cover = form.get("cover");
    if (cover instanceof File && !cover.size) form.delete("cover");
    if (form.get("remove_cover")) form.set("remove_cover", "1");
    setBusy(true);
    try {
      if (list) await api.updateCollection(list.id, form);
      else await api.createCollection(form);
      await onSaved();
      toast.success("Коллекция сохранена");
    } catch (error) {
      toast.error(errorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="form-stack">
      <Field label="Название">
        <Input
          name="name"
          required
          maxLength={255}
          defaultValue={list?.name || ""}
          placeholder="Например, кино на выходные"
        />
      </Field>
      <Field label="Описание">
        <Textarea
          name="description"
          maxLength={5000}
          defaultValue={list?.description || ""}
          placeholder="Что объединяет эти истории?"
        />
      </Field>
      <Field label="Обложка" hint="JPEG, PNG или WebP, до 5 МБ">
        <Input
          name="cover"
          type="file"
          accept="image/jpeg,image/png,image/webp"
        />
      </Field>
      {list?.cover_url && (
        <label className="check-label select-none">
          <Checkbox name="remove_cover" />
          Удалить обложку
        </label>
      )}
      <label className="check-label select-none">
        <Checkbox
          name="is_public"
          defaultChecked={list?.is_public || false}
        />
        Публичная — доступна по ссылке
      </label>
      <div className="form-actions">
        <Button variant="primary" disabled={busy}>
          {busy ? "Сохраняем…" : "Сохранить коллекцию"}
        </Button>
        <Button variant="secondary" type="button" onClick={onCancel}>
          Отмена
        </Button>
      </div>
    </form>
  );
}

export function CollectionDetail({
  publicToken = false,
}: {
  publicToken?: boolean;
}) {
  const params = useParams<{ id: string; token: string }>();
  const { user, loading } = useAuth();
  const router = useRouter();
  const cache = useQueryClient();
  const [edit, setEdit] = useState(false);
  const [remove, setRemove] = useState(false);
  const [busy, setBusy] = useState(false);

  const data = useQuery({
    queryKey: ["collection", publicToken, params.id || params.token, user?.id],
    queryFn: () =>
      publicToken
        ? api.publicCollection(params.token)
        : api.collectionById(Number(params.id)),
    enabled: !loading,
  });

  const list = data.data;
  const owner = list?.user_id === user?.id;

  const refresh = async () => {
    await Promise.all([
      cache.invalidateQueries({ queryKey: ["collections"] }),
      cache.invalidateQueries({ queryKey: ["collection"] }),
      cache.invalidateQueries({ queryKey: ["profile"] }),
    ]);
  };

  if (loading || data.isPending) return <Loading />;

  if (data.error || !list)
    return (
      <>
        <ErrorState error={data.error} />
        <Link
          className="button secondary"
          href={user ? "/collections" : "/login"}
        >
          {user ? "К моим коллекциям" : "Войти в аккаунт"}
        </Link>
      </>
    );

  return (
    <>
      <PageHeading
        eyebrow={list.is_public ? "ПУБЛИЧНАЯ ПОДБОРКА" : "ЛИЧНАЯ ПОДБОРКА"}
        title={list.name}
        description={`${list.media?.length || 0} историй в коллекции`}
      >
        {owner && (
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="secondary" onClick={() => setEdit(true)}>
              Редактировать
            </Button>
            <Button
              variant="secondary"
              className={dangerButton}
              onClick={() => setRemove(true)}
            >
              Удалить
            </Button>
          </div>
        )}
      </PageHeading>

      {list.description && (
        <p className="collection-description text-zinc-300! leading-relaxed">
          {list.description}
        </p>
      )}

      {list.is_public && list.share_token && (
        <div className="mb-6 flex flex-wrap items-center gap-3 rounded-2xl border border-white/10 bg-[#151921]/80 p-4 shadow-[0_10px_30px_rgba(0,0,0,0.25)] backdrop-blur-md">
          <span className="text-sm font-semibold text-gold">
            Поделись этой коллекцией
          </span>
          <Button
            variant="secondary"
            className={compactButton}
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(
                  window.location.origin +
                    "/public/lists/" +
                    list.share_token,
                );
                toast.success("Ссылка скопирована");
              } catch {
                toast.error("Не удалось скопировать ссылку");
              }
            }}
          >
            Скопировать ссылку
          </Button>
          <Link
            href={"/public/lists/" + list.share_token}
            className="group ml-auto inline-flex items-center gap-1.5 text-xs font-semibold text-zinc-400! transition-colors duration-200 hover:text-gold!"
          >
            Открыть публичную страницу{" "}
            <ArrowUpRightIcon
              className="ui-icon transition-transform duration-200 group-hover:-translate-y-0.5 group-hover:translate-x-0.5"
              aria-hidden="true"
            />
          </Link>
        </div>
      )}

      {list.media?.length ? (
        <div className="media-grid">
          {list.media.map((media) => (
            <div className="collection-item flex flex-col" key={media.id}>
              <MediaCard media={media} />
              {owner && (
                <Button
                  variant="ghost"
                  disabled={busy}
                  className="mt-2 min-h-9! w-full gap-1.5! rounded-lg! px-3! py-2! text-xs! text-red-400! enabled:hover:bg-red-500/10! enabled:hover:text-red-300!"
                  onClick={async () => {
                    setBusy(true);
                    try {
                      await api.removeFromCollection(list.id, media.id!);
                      await refresh();
                      toast.success("Удалено из коллекции");
                    } catch (error) {
                      toast.error(errorMessage(error));
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  <TrashIcon className="size-3.5" aria-hidden="true" /> Убрать
                </Button>
              )}
            </div>
          ))}
        </div>
      ) : (
        <Empty title="В коллекции пока нет кино">
          {owner && (
            <>
              <p>Открой карточку фильма и нажми «В коллекцию».</p>
              <Link className="button" href="/catalog">
                Найти фильм
              </Link>
            </>
          )}
        </Empty>
      )}

      {edit && (
        <Modal title="Редактировать коллекцию" onClose={() => setEdit(false)}>
          <CollectionForm
            list={list}
            onSaved={async () => {
              setEdit(false);
              await refresh();
            }}
            onCancel={() => setEdit(false)}
          />
        </Modal>
      )}

      {remove && (
        <Modal title="Удалить коллекцию?" onClose={() => setRemove(false)}>
          <p className="leading-relaxed text-zinc-300">
            Коллекция «{list.name}» будет удалена. Личные оценки и прогресс
            просмотра сохранятся.
          </p>
          <div className="form-actions">
            <Button
              variant="secondary"
              className={dangerButton}
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  await api.deleteCollection(list.id);
                  await refresh();
                  router.push("/collections");
                  toast.success("Коллекция удалена");
                } catch (error) {
                  toast.error(errorMessage(error));
                } finally {
                  setBusy(false);
                }
              }}
            >
              Удалить коллекцию
            </Button>
            <Button variant="ghost" onClick={() => setRemove(false)}>
              Отмена
            </Button>
          </div>
        </Modal>
      )}
    </>
  );
}