// frontend/components/ui/AddToListModal.tsx
'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { listsApi, UserList } from '@/lib/api/lists';
import toast from 'react-hot-toast';
import {
  XMarkIcon,
  PlusIcon,
  ArrowRightIcon,
  LockClosedIcon,
  GlobeAltIcon,
  CheckIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const EASE_EDITORIAL = [0.76, 0, 0.24, 1] as const;

interface AddToListModalProps {
  mediaId: number;
  mediaTitle: string;
  onClose: () => void;
}

function plural(n: number, one: string, few: string, many: string) {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return one;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return few;
  return many;
}

export default function AddToListModal({
  mediaId,
  mediaTitle,
  onClose,
}: AddToListModalProps) {
  const prefersReduced = useReducedMotion();
  const [lists, setLists] = useState<UserList[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateForm, setShowCreateForm] = useState(false);

  const [newListName, setNewListName] = useState('');
  const [isPublic, setIsPublic] = useState(false);
  const [creating, setCreating] = useState(false);

  const [addingToListId, setAddingToListId] = useState<number | null>(null);

  useEffect(() => {
    const fetchLists = async () => {
      try {
        setLoading(true);
        const data = await listsApi.getList();
        setLists(Array.isArray(data) ? data : []);
      } catch (error) {
        toast.error('Не удалось загрузить списки');
        setLists([]);
      } finally {
        setLoading(false);
      }
    };

    fetchLists();
  }, []);

  // Escape to close
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    const orig = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = orig;
    };
  }, [onClose]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newListName.trim()) {
      toast.error('Введите название списка');
      return;
    }

    setCreating(true);
    try {
      const newList = await listsApi.create({ name: newListName, is_public: isPublic });
      toast.success('Список создан!');

      setLists([newList, ...lists]);

      setNewListName('');
      setIsPublic(false);
      setShowCreateForm(false);

      await handleAddToList(newList.id);
    } catch (error) {
      toast.error('Ошибка создания списка');
    } finally {
      setCreating(false);
    }
  };

  const handleAddToList = async (listId: number) => {
    setAddingToListId(listId);
    try {
      await listsApi.addMedia(listId, mediaId);
      toast.success(`Добавлено в список!`);
      onClose();
    } catch (error: any) {
      const message = error.response?.data?.message || 'Ошибка добавления';
      toast.error(message);
    } finally {
      setAddingToListId(null);
    }
  };

  const handleBackdropClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (e.target === e.currentTarget) onClose();
    },
    [onClose]
  );

  return (
    <AnimatePresence>
      <motion.div
        className="fixed inset-0 z-50 flex items-center justify-center px-4 py-8 bg-black/60 backdrop-blur-sm"
        initial={prefersReduced ? false : { opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={prefersReduced ? undefined : { opacity: 0 }}
        transition={{ duration: 0.35, ease: EASE_OUT }}
        onClick={handleBackdropClick}
        role="dialog"
        aria-modal="true"
        aria-labelledby="add-to-list-title"
      >
        <motion.div
          className="relative w-full max-w-[560px] max-h-[90vh] bg-[var(--bg-primary)] border border-[var(--line)] flex flex-col"
          initial={prefersReduced ? false : { opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          exit={prefersReduced ? undefined : { opacity: 0, y: 16 }}
          transition={{ duration: 0.5, ease: EASE_EDITORIAL }}
        >
          {/* Верхняя редакционная полоса */}
          <div className="px-6 sm:px-8 pt-6 pb-4 border-b border-[var(--line)]">
            <div className="flex items-center justify-between pb-4 border-b border-[var(--line)] font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
              <span>Добавить в список</span>
              <button
                type="button"
                onClick={onClose}
                aria-label="Закрыть"
                className="group inline-flex items-center gap-2 hover:text-[var(--text-primary)] transition-colors"
              >
                <span className="hidden sm:inline">Закрыть</span>
                <XMarkIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:rotate-90" />
              </button>
            </div>

            <div className="pt-6">
              <h2
                id="add-to-list-title"
                className="font-serif text-2xl sm:text-3xl leading-[0.95] tracking-[-0.02em] text-[var(--text-primary)] line-clamp-2"
              >
                {mediaTitle}
              </h2>
              <p className="mt-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                Выберите подборку
              </p>
            </div>
          </div>

          {/* Тело — скроллируется */}
          <div className="flex-1 overflow-y-auto px-6 sm:px-8 py-6">
            {/* ===== Форма создания ===== */}
            {showCreateForm ? (
              <motion.div
                initial={prefersReduced ? false : { opacity: 0, y: -6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, ease: EASE_OUT }}
                className="mb-8 pb-8 border-b border-[var(--line)]"
              >
                <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-4">
                  Новая подборка
                </p>

                <form onSubmit={handleCreate} className="space-y-6">
                  <div>
                    <label
                      htmlFor="new-list-name"
                      className="block font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] mb-1"
                    >
                      Название
                    </label>
                    <input
                      id="new-list-name"
                      type="text"
                      value={newListName}
                      onChange={(e) => setNewListName(e.target.value)}
                      placeholder="Например: Топ-10 триллеров"
                      className="w-full bg-transparent border-0 border-b border-[var(--line)] rounded-none px-0 py-2.5 text-lg font-serif tracking-[-0.005em] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] placeholder:italic placeholder:opacity-60 focus:outline-none focus:border-[var(--accent-yellow)] transition-colors"
                      autoFocus
                      disabled={creating}
                    />
                  </div>

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
                      disabled={creating}
                    />
                    <span className="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
                      {isPublic ? (
                        <GlobeAltIcon className="w-3.5 h-3.5" />
                      ) : (
                        <LockClosedIcon className="w-3.5 h-3.5" />
                      )}
                      Публичный список
                    </span>
                  </label>

                  <div className="flex items-center gap-6 pt-2">
                    <button
                      type="submit"
                      disabled={creating}
                      className="group inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-primary)] border-b border-[var(--text-primary)] pb-0.5 hover:border-[var(--accent-yellow)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      {creating ? 'Создание…' : 'Создать и добавить'}
                      {creating ? (
                        <ArrowPathIcon className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <ArrowRightIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:translate-x-0.5" />
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowCreateForm(false)}
                      className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                    >
                      Отмена
                    </button>
                  </div>
                </form>
              </motion.div>
            ) : (
              <button
                type="button"
                onClick={() => setShowCreateForm(true)}
                className="group w-full flex items-center justify-between py-3.5 mb-8 border-y border-[var(--line)] hover:border-[var(--text-primary)] transition-colors"
              >
                <span className="flex items-center gap-3">
                  <span className="w-8 h-8 rounded-full bg-[var(--text-primary)] text-[var(--bg-primary)] grid place-items-center transition-transform duration-500 group-hover:rotate-[-8deg] group-hover:scale-105">
                    <PlusIcon className="w-4 h-4" />
                  </span>
                  <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-primary)]">
                    Создать новый список
                  </span>
                </span>
                <ArrowRightIcon className="w-4 h-4 text-[var(--text-muted)] transition-transform duration-500 group-hover:translate-x-0.5" />
              </button>
            )}

            {/* ===== Список существующих ===== */}
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-4">
                Ваши списки
              </p>

              {loading ? (
                <div className="space-y-3">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <div key={i} className="animate-pulse space-y-2 py-2">
                      <div className="h-4 w-2/3 bg-[var(--bg-tertiary)] rounded" />
                      <div className="h-2.5 w-1/3 bg-[var(--bg-tertiary)] rounded" />
                    </div>
                  ))}
                </div>
              ) : lists.length === 0 ? (
                <div className="py-6 text-center">
                  <p className="text-sm text-[var(--text-muted)]">
                    У вас пока нет списков. Создайте первый!
                  </p>
                </div>
              ) : (
                <ul>
                  {lists.map((list, i) => {
                    const isAdding = addingToListId === list.id;
                    const isBusy = addingToListId !== null && !isAdding;
                    return (
                      <motion.li
                        key={list.id}
                        initial={prefersReduced ? false : { opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{
                          duration: 0.4,
                          delay: Math.min(i * 0.04, 0.3),
                          ease: EASE_OUT,
                        }}
                        className="border-b border-[var(--line)]"
                      >
                        <button
                          type="button"
                          onClick={() => handleAddToList(list.id)}
                          disabled={isAdding || isBusy}
                          className="group w-full flex items-center gap-4 py-4 text-left disabled:cursor-not-allowed"
                        >
                          <div className="flex-1 min-w-0">
                            <div className="flex items-baseline gap-2 flex-wrap">
                              <span className="font-serif text-lg leading-tight text-[var(--text-primary)] group-hover:italic transition-[font-style] duration-300 truncate">
                                {list.name}
                              </span>
                              {list.is_public && (
                                <span className="inline-flex items-center gap-1.5 shrink-0">
                                  <span className="w-1 h-1 rounded-full bg-[var(--accent-green)]" />
                                  <span className="font-mono text-[9px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                                    Публичный
                                  </span>
                                </span>
                              )}
                            </div>
                            <p className="mt-1.5 font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)]">
                              {list.media_count}{' '}
                              {plural(list.media_count, 'элемент', 'элемента', 'элементов')}
                            </p>
                          </div>

                          <span
                            className={`shrink-0 inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] transition-colors ${
                              isAdding
                                ? 'text-[var(--accent-yellow)]'
                                : 'text-[var(--text-muted)] group-hover:text-[var(--text-primary)]'
                            }`}
                          >
                            {isAdding ? (
                              <>
                                <ArrowPathIcon className="w-3.5 h-3.5 animate-spin" />
                                Добавление
                              </>
                            ) : (
                              <>
                                <span className="border-b border-transparent group-hover:border-[var(--text-primary)] pb-0.5 transition-colors">
                                  Добавить
                                </span>
                                <CheckIcon className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                              </>
                            )}
                          </span>
                        </button>
                      </motion.li>
                    );
                  })}
                </ul>
              )}
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}