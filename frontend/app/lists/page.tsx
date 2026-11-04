'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { motion, useReducedMotion } from 'framer-motion';
import { listsApi, UserList } from '@/lib/api/lists';
import {
  PlusIcon,
  ArrowRightIcon,
  ArrowUpRightIcon,
  TrashIcon,
  LockClosedIcon,
  GlobeAltIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

function plural(n: number, one: string, few: string, many: string) {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return one;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return few;
  return many;
}

export default function ListsPage() {
  const prefersReduced = useReducedMotion();
  const [lists, setLists] = useState<UserList[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateForm, setShowCreateForm] = useState(false);

  // Состояние для формы создания
  const [newListName, setNewListName] = useState('');
  const [isPublic, setIsPublic] = useState(false);
  const [creating, setCreating] = useState(false);

  const fetchLists = async () => {
    try {
      setLoading(true);
      const data = await listsApi.getList();
      setLists(data);
    } catch (error) {
      toast.error('Не удалось загрузить списки');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLists();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newListName.trim()) {
      toast.error('Введите название списка');
      return;
    }

    setCreating(true);
    try {
      await listsApi.create({ name: newListName, is_public: isPublic });
      toast.success('Список создан!');
      setNewListName('');
      setIsPublic(false);
      setShowCreateForm(false);
      fetchLists();
    } catch (error) {
      toast.error('Ошибка создания списка');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Вы уверены, что хотите удалить этот список?')) return;
    try {
      await listsApi.delete(id);
      toast.success('Список удален');
      fetchLists();
    } catch (error) {
      toast.error('Ошибка удаления');
    }
  };

  const totalCount = lists.length;

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      {/* ============ MASTHEAD ============ */}
      <section className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
            <Link
              href="/"
              className="group inline-flex items-center gap-2 hover:text-[var(--text-primary)] transition-colors"
            >
              <span className="inline-block transition-transform group-hover:-translate-x-0.5">
                ←
              </span>
              <span>В каталог</span>
            </Link>
            <span className="hidden sm:inline">
              Коллекции · {totalCount}
            </span>
          </div>
        </div>

        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-14 lg:pb-20">
          <div className="grid lg:grid-cols-12 gap-8 items-end">
            <motion.div
              className="lg:col-span-8"
              initial={prefersReduced ? false : { opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.9, ease: EASE_OUT }}
            >
              <h1 className="font-serif text-[clamp(3.5rem,14vw,12rem)] leading-[0.82] tracking-[-0.045em]">
                Мои списки<span className="text-[var(--accent-yellow)]">.</span>
              </h1>
            </motion.div>

            <motion.div
              className="lg:col-span-4 lg:text-right"
              initial={prefersReduced ? false : { opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.9, delay: 0.1, ease: EASE_OUT }}
            >
              <p className="text-base sm:text-lg text-[var(--text-secondary)] leading-relaxed max-w-xs lg:ml-auto">
                {totalCount === 0
                  ? 'Соберите первую подборку — тренды, classics, guilty pleasures.'
                  : `${totalCount} ${plural(
                      totalCount,
                      'подборка',
                      'подборки',
                      'подборок'
                    )} в вашей коллекции`}
              </p>
              <button
                onClick={() => setShowCreateForm(!showCreateForm)}
                className="group mt-6 inline-flex items-center gap-3"
              >
                <span className="w-11 h-11 rounded-full border border-[var(--line)] grid place-items-center transition-colors duration-300 group-hover:border-[var(--text-primary)] group-hover:bg-[var(--text-primary)] group-hover:text-[var(--bg-primary)]">
                  {showCreateForm ? (
                    <XMarkIcon className="w-5 h-5" />
                  ) : (
                    <PlusIcon className="w-5 h-5" />
                  )}
                </span>
                <span className="font-mono text-[11px] uppercase tracking-[0.2em] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
                  {showCreateForm ? 'Отмена' : 'Новый список'}
                </span>
              </button>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ============ CREATE FORM ============ */}
      {showCreateForm && (
        <motion.section
          initial={prefersReduced ? false : { opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          exit={{ opacity: 0, height: 0 }}
          transition={{ duration: 0.6, ease: EASE_OUT }}
          className="border-b border-[var(--line)] bg-[var(--bg-secondary)] overflow-hidden"
        >
          <form onSubmit={handleCreate}>
            <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-8 lg:py-10">
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
                Новая подборка
              </p>

              <div className="grid lg:grid-cols-12 gap-6 lg:gap-10 items-end">
                <div className="lg:col-span-7">
                  <label className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] block mb-2">
                    Название
                  </label>
                  <input
                    type="text"
                    value={newListName}
                    onChange={(e) => setNewListName(e.target.value)}
                    placeholder="Например: Топ-10 триллеров"
                    className="w-full bg-transparent border-0 border-b border-[var(--line)] rounded-none py-2 text-2xl sm:text-3xl font-serif tracking-[-0.01em] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] placeholder:italic focus:outline-none focus:border-[var(--accent-yellow)] transition-colors"
                    autoFocus
                  />
                </div>

                <div className="lg:col-span-3">
                  <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] mb-3">
                    Видимость
                  </p>
                  <label className="flex items-center gap-3 cursor-pointer group">
                    <span
                      className={`w-4 h-4 border transition-colors grid place-items-center shrink-0 ${
                        isPublic
                          ? 'bg-[var(--accent-yellow)] border-[var(--accent-yellow)]'
                          : 'border-[var(--line)] group-hover:border-[var(--text-primary)]'
                      }`}
                    >
                      {isPublic && <span className="w-1.5 h-1.5 bg-black" />}
                    </span>
                    <input
                      type="checkbox"
                      checked={isPublic}
                      onChange={(e) => setIsPublic(e.target.checked)}
                      className="sr-only"
                    />
                    <span className="text-sm text-[var(--text-secondary)] flex items-center gap-2">
                      {isPublic ? (
                        <GlobeAltIcon className="w-4 h-4" />
                      ) : (
                        <LockClosedIcon className="w-4 h-4" />
                      )}
                      Публичный (по ссылке)
                    </span>
                  </label>
                </div>

                <div className="lg:col-span-2 lg:text-right">
                  <button
                    type="submit"
                    disabled={creating}
                    className="group inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-primary)] border-b border-[var(--text-primary)] pb-0.5 hover:border-[var(--accent-yellow)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    {creating ? 'Создание…' : 'Создать'}
                    <ArrowRightIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:translate-x-0.5" />
                  </button>
                </div>
              </div>
            </div>
          </form>
        </motion.section>
      )}

      {/* ============ LISTS INDEX ============ */}
      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 py-12 lg:py-16">
        {loading ? (
          <SkeletonList />
        ) : lists.length === 0 ? (
          <EmptyState onCreate={() => setShowCreateForm(true)} />
        ) : (
          <>
            <div className="flex items-center justify-between pb-3 border-b border-[var(--line)]">
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                Все подборки
              </p>
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                {new Date().getFullYear()}
              </p>
            </div>

            <ul>
              {lists.map((list, i) => (
                <motion.li
                  key={list.id}
                  initial={prefersReduced ? false : { opacity: 0, y: 14 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{
                    duration: 0.55,
                    delay: Math.min(i * 0.05, 0.4),
                    ease: EASE_OUT,
                  }}
                  className="border-b border-[var(--line)]"
                >
                  <ListItem
                    list={list}
                    index={i}
                    onDelete={() => handleDelete(list.id)}
                  />
                </motion.li>
              ))}
            </ul>
          </>
        )}
      </section>
    </div>
  );
}

/* ---------- Строка списка ---------- */

function ListItem({
  list,
  index,
  onDelete,
}: {
  list: UserList;
  index: number;
  onDelete: () => void;
}) {
  return (
    <div className="relative group">
      <Link
        href={`/lists/${list.id}`}
        className="grid grid-cols-[auto_1fr_auto] items-center gap-4 sm:gap-6 lg:gap-10 py-7 lg:py-9 pr-10 sm:pr-14"
      >
        {/* Индекс */}
        <div className="hidden sm:block font-mono text-[10px] tracking-[0.2em] text-[var(--text-muted)] min-w-[28px] pt-1">
          {String(index + 1).padStart(2, '0')}
        </div>

        {/* Название */}
        <div className="min-w-0">
          <div className="flex items-baseline gap-3 flex-wrap">
            <h3 className="font-serif text-2xl sm:text-3xl lg:text-4xl leading-[1.05] tracking-[-0.015em] group-hover:italic transition-[font-style] duration-300">
              {list.name}
            </h3>
            {list.is_public && (
              <span className="inline-flex items-center gap-1.5 shrink-0 translate-y-[-4px]">
                <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-green)]" />
                <span className="font-mono text-[9px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                  Публичный
                </span>
              </span>
            )}
          </div>

          <p className="mt-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
            {list.media_count}{' '}
            {plural(list.media_count, 'элемент', 'элемента', 'элементов')}
          </p>
        </div>

        {/* Стрелка */}
        <div className="flex items-center">
          <span className="w-10 h-10 rounded-full border border-[var(--line)] grid place-items-center transition-all duration-500 group-hover:border-[var(--text-primary)] group-hover:bg-[var(--text-primary)] group-hover:text-[var(--bg-primary)]">
            <ArrowUpRightIcon className="w-4 h-4 transition-transform duration-500 group-hover:rotate-45" />
          </span>
        </div>
      </Link>

      <button
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          onDelete();
        }}
        aria-label="Удалить список"
        title="Удалить список"
        className="absolute top-7 lg:top-9 right-0 w-8 h-8 flex items-center justify-center text-[var(--text-muted)] opacity-0 group-hover:opacity-100 focus-visible:opacity-100 hover:text-[var(--accent-red)] transition-all"
      >
        <TrashIcon className="w-4 h-4" />
      </button>
    </div>
  );
}

/* ---------- Skeleton ---------- */

function SkeletonList() {
  return (
    <ul>
      {Array.from({ length: 4 }).map((_, i) => (
        <li
          key={i}
          className="grid grid-cols-[auto_1fr_auto] items-center gap-4 sm:gap-6 lg:gap-10 py-7 lg:py-9 border-b border-[var(--line)] animate-pulse"
        >
          <div className="hidden sm:block w-6 h-2 bg-[var(--bg-tertiary)] rounded" />
          <div className="flex-1 space-y-3">
            <div className="h-6 w-2/3 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-2.5 w-1/4 bg-[var(--bg-tertiary)] rounded" />
          </div>
          <div className="w-10 h-10 rounded-full bg-[var(--bg-tertiary)]" />
        </li>
      ))}
    </ul>
  );
}

/* ---------- Пустой стейт ---------- */

function EmptyState({ onCreate }: { onCreate: () => void }) {
  return (
    <div className="py-24 lg:py-32 text-center border-y border-[var(--line)]">
      <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
        Пусто
      </p>
      <h2 className="font-serif text-4xl sm:text-5xl tracking-[-0.02em] mb-4">
        У вас пока нет списков
      </h2>
      <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
        Создайте первую подборку — например, «Топ-10 триллеров» или «Фильмы для дождливого вечера».
      </p>
      <div className="mt-10 flex justify-center">
        <button
          onClick={onCreate}
          className="group inline-flex items-center gap-3"
        >
          <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
            Создать список
          </span>
          <span className="w-10 h-10 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
            <PlusIcon className="w-4 h-4 transition-transform duration-500 group-hover:rotate-90" />
          </span>
        </button>
      </div>
    </div>
  );
}