"use client";

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
  Empty,
  ErrorState,
  Field,
  Loading,
  MediaCard,
  Modal,
  PageHeading,
} from "./UI";

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
        <button className="button" onClick={() => setCreate(true)}>
          + Создать коллекцию
        </button>
      </PageHeading>
      {data.isPending ? (
        <Loading />
      ) : data.error ? (
        <ErrorState error={data.error} retry={() => data.refetch()} />
      ) : data.data.length ? (
        <div className="collections-grid">
          {data.data.map((list) => (
            <Link
              className="collection-card panel"
              key={list.id}
              href={"/collections/" + list.id}
            >
              {list.cover_url ? (
                <Artwork
                  className="collection-cover"
                  src={list.cover_url}
                  alt={list.name}
                />
              ) : (
                <div className="collection-cover artwork-placeholder">
                  ▧<span>Твоя подборка кино</span>
                </div>
              )}
              <h3>{list.name}</h3>
              <p>{list.description || "Истории, которые стоит сохранить."}</p>
              <div className="row">
                <small>{list.media_count} записей</small>
                <span className={"pill " + (list.is_public ? "green" : "")}>
                  {list.is_public ? "Публичная" : "Личная"}
                </span>
              </div>
            </Link>
          ))}
        </div>
      ) : (
        <Empty title="Собери первую коллекцию">
          <p>Добавляй фильмы и сериалы с любой карточки.</p>
          <button className="button" onClick={() => setCreate(true)}>
            Создать коллекцию
          </button>
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
        <input
          name="name"
          required
          maxLength={255}
          defaultValue={list?.name || ""}
          placeholder="Например, кино на выходные"
        />
      </Field>
      <Field label="Описание">
        <textarea
          name="description"
          maxLength={5000}
          defaultValue={list?.description || ""}
          placeholder="Что объединяет эти истории?"
        />
      </Field>
      <Field label="Обложка" hint="JPEG, PNG или WebP, до 5 МБ">
        <input
          name="cover"
          type="file"
          accept="image/jpeg,image/png,image/webp"
        />
      </Field>
      {list?.cover_url && (
        <label className="check-label">
          <input type="checkbox" name="remove_cover" />
          Удалить обложку
        </label>
      )}
      <label className="check-label">
        <input
          name="is_public"
          type="checkbox"
          defaultChecked={list?.is_public || false}
        />
        Публичная — доступна по ссылке
      </label>
      <div className="form-actions">
        <button className="button" disabled={busy}>
          {busy ? "Сохраняем…" : "Сохранить коллекцию"}
        </button>
        <button className="button secondary" type="button" onClick={onCancel}>
          Отмена
        </button>
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
          <div className="form-actions">
            <button className="button secondary" onClick={() => setEdit(true)}>
              Редактировать
            </button>
            <button className="button danger" onClick={() => setRemove(true)}>
              Удалить
            </button>
          </div>
        )}
      </PageHeading>
      {list.description && (
        <p className="collection-description">{list.description}</p>
      )}
      {list.is_public && list.share_token && (
        <div className="notice">
          <div className="form-actions">
            <span>Поделись этой коллекцией</span>
            <button
              className="button secondary small"
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
            </button>
            <Link href={"/public/lists/" + list.share_token}>
              Открыть публичную страницу ↗
            </Link>
          </div>
        </div>
      )}
      {list.media?.length ? (
        <div className="media-grid">
          {list.media.map((media) => (
            <div className="collection-item" key={media.id}>
              <MediaCard media={media} />
              {owner && (
                <button
                  className="button secondary small"
                  disabled={busy}
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
                  Убрать из коллекции
                </button>
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
          <p>
            Коллекция «{list.name}» будет удалена. Личные оценки и прогресс
            просмотра сохранятся.
          </p>
          <div className="form-actions">
            <button
              className="button danger"
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
            </button>
            <button
              className="button secondary"
              onClick={() => setRemove(false)}
            >
              Отмена
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
