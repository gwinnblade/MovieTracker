// frontend/components/ui/EntryForm.tsx
'use client';

import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { entriesApi, STATUS_MAP, Entry } from '@/lib/api/entries';
import { useAuthStore } from '@/store/useAuthStore';
import { motion, useReducedMotion } from 'framer-motion';
import toast from 'react-hot-toast';
import {
  XMarkIcon,
  TrashIcon,
  CheckIcon,
  ArrowRightIcon,
  ArrowPathIcon,
  StarIcon,
} from '@heroicons/react/24/outline';

interface EntryFormProps {
  mediaId: number;
  mediaTitle: string;
  existingEntry?: Entry | null;
  onClose: () => void;
  onSuccess: () => void;
}

const NOTE_MAX = 2000;
const DEFAULT_STATUS_ID = 2;

const STATUS_ACCENT: Record<string, string> = {
  yellow: 'var(--accent-yellow)',
  green: 'var(--accent-green)',
  purple: 'var(--accent-purple)',
  red: 'var(--accent-red)',
  blue: 'var(--accent-blue)',
  orange: 'var(--accent-orange)',
  pink: 'var(--accent-pink)',
};

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const EASE_EDITORIAL = [0.76, 0, 0.24, 1] as const;

function getTodayLocal(): string {
  return new Date().toLocaleDateString('en-CA');
}

export default function EntryForm({
  mediaId,
  mediaTitle,
  existingEntry,
  onClose,
  onSuccess,
}: EntryFormProps) {
  const prefersReduced = useReducedMotion();
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);

  const [statusId, setStatusId] = useState<number>(
    existingEntry?.status_id ?? DEFAULT_STATUS_ID
  );
  const [rating, setRating] = useState<number | null>(existingEntry?.rating ?? null);
  const [date, setDate] = useState(existingEntry?.date || getTodayLocal());
  const [note, setNote] = useState(existingEntry?.note ?? '');
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const dialogRef = useRef<HTMLDivElement>(null);
  const previousFocus = useRef<HTMLElement | null>(null);

  useEffect(() => {
    previousFocus.current = document.activeElement as HTMLElement;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const first = dialogRef.current?.querySelector<HTMLElement>(
      'button:not([disabled]), input:not([disabled]), textarea:not([disabled])'
    );
    first?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== 'Tab') return;
      const focusables = dialogRef.current?.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      );
      if (!focusables || focusables.length === 0) return;
      const firstEl = focusables[0];
      const lastEl = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === firstEl) {
        e.preventDefault();
        lastEl.focus();
      } else if (!e.shiftKey && document.activeElement === lastEl) {
        e.preventDefault();
        firstEl.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = prevOverflow;
      previousFocus.current?.focus();
    };
  }, [onClose]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isAuthenticated) {
      toast.error('Войдите в систему');
      return;
    }
    if (saving || deleting) return;

    setSaving(true);
    try {
      await entriesApi.save({
        media_id: mediaId,
        status_id: statusId,
        rating,
        date,
        note: note.trim() || null,
      });
      toast.success(existingEntry ? 'Отметка обновлена' : 'Отметка добавлена');
      onSuccess();
    } catch (error: any) {
      const msg =
        error?.response?.data?.message ??
        (error?.response ? 'Не удалось сохранить' : 'Нет соединения');
      toast.error(msg);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = () => {
    if (!existingEntry || saving || deleting) return;
    toast(
      (t) => (
        <span className="flex items-center gap-3 text-sm">
          <span>Удалить отметку?</span>
          <button
            onClick={() => {
              toast.dismiss(t.id);
              doDelete();
            }}
            className="font-semibold text-[var(--accent-red)] hover:underline"
          >
            Удалить
          </button>
          <button
            onClick={() => toast.dismiss(t.id)}
            className="text-[var(--text-muted)] hover:underline"
          >
            Отмена
          </button>
        </span>
      ),
      { duration: 6000 }
    );
  };

  const doDelete = async () => {
    if (!existingEntry) return;
    setDeleting(true);
    try {
      await entriesApi.delete(existingEntry.id);
      toast.success('Отметка удалена');
      onSuccess();
    } catch {
      toast.error('Не удалось удалить');
    } finally {
      setDeleting(false);
    }
  };

  if (typeof window === 'undefined') return null;

  const statusEntries = Object.entries(STATUS_MAP);

  return createPortal(
    <motion.div
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      className="fixed inset-0 z-[100] flex items-end sm:items-center justify-center p-0 sm:p-4 bg-black/60 backdrop-blur-sm"
      initial={prefersReduced ? false : { opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.35, ease: EASE_OUT }}
    >
      <motion.div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="entry-form-title"
        className="w-full max-w-[640px] max-h-[92vh] flex flex-col bg-[var(--bg-primary)] border border-[var(--line)] sm:border sm:max-h-[90vh]"
        initial={prefersReduced ? false : { opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: EASE_EDITORIAL }}
      >
        {/* ===== Шапка ===== */}
        <div className="shrink-0 border-b border-[var(--line)]">
          <div className="px-6 sm:px-8 pt-6 pb-4">
            <div className="flex items-center justify-between pb-4 border-b border-[var(--line)] font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
              <span>{existingEntry ? 'Редактирование отметки' : 'Новая отметка'}</span>
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
                id="entry-form-title"
                className="font-serif text-3xl sm:text-4xl leading-[0.9] tracking-[-0.03em] text-[var(--text-primary)] break-words"
              >
                {existingEntry ? 'Изменить' : 'Отметить'}
                <span className="text-[var(--accent-yellow)]">.</span>
              </h2>
              <p className="mt-3 font-serif italic text-base text-[var(--text-secondary)] truncate">
                {mediaTitle}
              </p>
            </div>
          </div>
        </div>

        {/* ===== Тело формы ===== */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto">
          <div className="px-6 sm:px-8 py-8 space-y-12">
            {/* ===== Статус ===== */}
            <fieldset>
              <legend className="block w-full pb-3 mb-4 border-b border-[var(--line)]">
                <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                  Статус
                </span>
              </legend>

              <div className="flex flex-col sm:flex-row sm:flex-wrap gap-x-6 gap-y-1">
                {statusEntries.map(([id, info], i) => {
                  const isActive = statusId === Number(id);
                  const accent = STATUS_ACCENT[info.color] ?? 'var(--text-primary)';
                  return (
                    <button
                      key={id}
                      type="button"
                      onClick={() => setStatusId(Number(id))}
                      aria-pressed={isActive}
                      disabled={saving || deleting}
                      className="group relative flex items-baseline gap-3 py-2 sm:py-1.5 text-left disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <span className="font-mono text-[10px] tracking-[0.2em] text-[var(--text-muted)] tabular-nums shrink-0">
                        {String(i + 1).padStart(2, '0')}
                      </span>
                      <span
                        className={`w-1.5 h-1.5 rounded-full shrink-0 self-center transition-colors ${
                          isActive ? '' : 'opacity-50'
                        }`}
                        style={{ background: accent }}
                      />
                      <span
                        className={`font-serif text-lg leading-tight transition-colors ${
                          isActive
                            ? 'text-[var(--text-primary)] italic'
                            : 'text-[var(--text-secondary)] group-hover:text-[var(--text-primary)]'
                        }`}
                      >
                        {info.name}
                      </span>
                      {isActive && (
                        <CheckIcon
                          className="w-3.5 h-3.5 shrink-0 text-[var(--text-primary)]"
                          aria-hidden="true"
                        />
                      )}
                    </button>
                  );
                })}
              </div>
            </fieldset>

            {/* ===== Оценка ===== */}
            <fieldset>
              <legend className="flex items-baseline justify-between w-full pb-3 mb-4 border-b border-[var(--line)]">
                <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                  Оценка
                </span>
                <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)] tabular-nums">
                  {rating != null ? (
                    <>
                      <span className="font-serif text-lg text-[var(--accent-yellow)] not-italic">
                        {rating}
                      </span>
                      <span className="text-[var(--text-muted)]"> / 10</span>
                    </>
                  ) : (
                    <span className="text-[var(--text-muted)]">не поставлена</span>
                  )}
                </span>
              </legend>

              <div className="grid grid-cols-10 gap-1 sm:gap-1.5">
                {Array.from({ length: 10 }, (_, i) => i + 1).map((n) => {
                  const active = rating === n;
                  const isPast = rating != null && rating >= n;
                  return (
                    <button
                      key={n}
                      type="button"
                      onClick={() => setRating(rating === n ? null : n)}
                      aria-label={`${n} из 10`}
                      aria-pressed={active}
                      disabled={saving || deleting}
                      className={`group relative aspect-square flex items-center justify-center border-b-2 transition-colors duration-500 disabled:opacity-50 disabled:cursor-not-allowed ${
                        active
                          ? 'border-[var(--accent-yellow)] bg-[var(--accent-yellow)]/10'
                          : isPast
                            ? 'border-[var(--text-primary)]'
                            : 'border-[var(--line)] hover:border-[var(--text-secondary)]'
                      }`}
                    >
                      <span
                        className={`font-serif text-sm sm:text-base tabular-nums transition-colors ${
                          active
                            ? 'text-[var(--text-primary)]'
                            : isPast
                              ? 'text-[var(--text-primary)]'
                              : 'text-[var(--text-muted)] group-hover:text-[var(--text-secondary)]'
                        }`}
                      >
                        {n}
                      </span>
                    </button>
                  );
                })}
              </div>

              {rating != null && (
                <button
                  type="button"
                  onClick={() => setRating(null)}
                  disabled={saving || deleting}
                  className="mt-3 font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)] hover:text-[var(--accent-red)] border-b border-transparent hover:border-[var(--accent-red)] pb-0.5 transition-colors disabled:opacity-50"
                >
                  Сбросить оценку
                </button>
              )}
            </fieldset>

            {/* ===== Дата ===== */}
            <div>
              <label
                htmlFor="entry-date"
                className="block font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] mb-1"
              >
                Дата
              </label>
              <input
                id="entry-date"
                type="date"
                value={date}
                onChange={(e) => setDate(e.target.value)}
                disabled={saving || deleting}
                className="w-full sm:max-w-[240px] bg-transparent border-0 border-b border-[var(--line)] rounded-none px-0 py-2.5 font-serif text-lg text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-yellow)] transition-colors disabled:opacity-50"
              />
            </div>

            {/* ===== Заметка ===== */}
            <div>
              <div className="flex items-baseline justify-between mb-1">
                <label
                  htmlFor="entry-note"
                  className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]"
                >
                  Заметка
                </label>
                <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)] tabular-nums">
                  {note.length}/{NOTE_MAX}
                </span>
              </div>
              <textarea
                id="entry-note"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                rows={4}
                maxLength={NOTE_MAX}
                placeholder="Ваши впечатления…"
                disabled={saving || deleting}
                className="w-full bg-transparent border-0 border-b border-[var(--line)] rounded-none px-0 py-3 font-serif text-base sm:text-lg leading-relaxed text-[var(--text-primary)] placeholder:text-[var(--text-muted)] placeholder:italic placeholder:opacity-60 focus:outline-none focus:border-[var(--accent-yellow)] resize-none transition-colors disabled:opacity-50"
              />
            </div>
          </div>

          {/* ===== Действия — фиксированные внизу ===== */}
          <div className="sticky bottom-0 bg-[var(--bg-primary)] border-t border-[var(--line)] px-6 sm:px-8 py-4 flex flex-col-reverse sm:flex-row sm:items-center sm:justify-between gap-4">
            {existingEntry ? (
              <button
                type="button"
                onClick={handleDelete}
                disabled={saving || deleting}
                className="inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)] hover:text-[var(--accent-red)] border-b border-transparent hover:border-[var(--accent-red)] pb-0.5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed self-start sm:self-auto"
              >
                {deleting ? (
                  <ArrowPathIcon className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <TrashIcon className="w-3.5 h-3.5" />
                )}
                {deleting ? 'Удаляем…' : 'Удалить'}
              </button>
            ) : (
              <div className="hidden sm:block" />
            )}

            <div className="flex items-center gap-6">
              <button
                type="button"
                onClick={onClose}
                disabled={saving || deleting}
                className="font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors disabled:opacity-40"
              >
                Отмена
              </button>

              <button
                type="submit"
                disabled={saving || deleting}
                className="group inline-flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.22em] text-[var(--text-primary)] border-b border-[var(--text-primary)] pb-0.5 hover:border-[var(--accent-yellow)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {saving ? (
                  <>
                    Сохраняем…
                    <ArrowPathIcon className="w-3.5 h-3.5 animate-spin" />
                  </>
                ) : (
                  <>
                    {existingEntry ? 'Обновить' : 'Сохранить'}
                    <ArrowRightIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:translate-x-0.5" />
                  </>
                )}
              </button>
            </div>
          </div>
        </form>
      </motion.div>
    </motion.div>,
    document.body
  );
}