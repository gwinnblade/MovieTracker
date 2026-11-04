'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { motion, useReducedMotion } from 'framer-motion';
import { moderationApi, ModerationRequest } from '@/lib/api/moderation';
import toast from 'react-hot-toast';
import {
  CheckCircleIcon,
  XCircleIcon,
  InboxIcon,
  ArrowPathIcon,
  ChevronLeftIcon,
  UserIcon,
  CalendarDaysIcon,
  ClockIcon,
  MagnifyingGlassIcon,
  ArrowRightIcon,
} from '@heroicons/react/24/outline';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const EASE_EDITORIAL = [0.76, 0, 0.24, 1] as const;

type Status = 'pending' | 'approved' | 'rejected';
type Processing = 'approve' | 'reject';

const TYPE_ACCENTS: Record<string, string> = {
  'Фильм': 'var(--accent-yellow)',
  'Сериал': 'var(--accent-blue, #6a8fc4)',
  'Аниме': 'var(--accent-green)',
  'Мультфильм': 'var(--accent-purple)',
};

function formatRelative(dateStr: string): string {
  const d = new Date(dateStr);
  const diff = Date.now() - d.getTime();
  const min = Math.floor(diff / 60_000);
  if (min < 1) return 'только что';
  if (min < 60) return `${min} мин назад`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h} ч назад`;
  const days = Math.floor(h / 24);
  if (days < 7) return `${days} дн назад`;
  return d.toLocaleDateString('ru-RU', { day: 'numeric', month: 'short' });
}

function plural(n: number, one: string, few: string, many: string) {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return one;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return few;
  return many;
}

export default function ModerationPage() {
  const prefersReduced = useReducedMotion();
  const [all, setAll] = useState<ModerationRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [tab, setTab] = useState<Status>('pending');
  const [sort, setSort] = useState<'oldest' | 'newest'>('oldest');
  const [rejectOpenId, setRejectOpenId] = useState<number | null>(null);
  const [rejectDraft, setRejectDraft] = useState<Record<number, string>>({});
  const [processing, setProcessing] = useState<Record<number, Processing>>({});

  const fetchRequests = async () => {
    try {
      setLoading(true);
      setFailed(false);
      const data = await moderationApi.getRequests();
      setAll(Array.isArray(data) ? data : []);
    } catch {
      setFailed(true);
      toast.error('Не удалось загрузить заявки');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRequests();
  }, []);

  const counts = useMemo(() => {
    const c: Record<Status, number> = { pending: 0, approved: 0, rejected: 0 };
    for (const r of all) {
      if (r.status === 'pending' || r.status === 'approved' || r.status === 'rejected') {
        c[r.status]++;
      }
    }
    return c;
  }, [all]);

  const visible = useMemo(() => {
    return all
      .filter((r) => r.status === tab)
      .sort((a, b) => {
        const da = new Date(a.created_at).getTime();
        const db = new Date(b.created_at).getTime();
        return sort === 'oldest' ? da - db : db - da;
      });
  }, [all, tab, sort]);

  const setStatusOptimistic = (id: number, status: Status) => {
    setAll((prev) => prev.map((r) => (r.id === id ? { ...r, status } : r)));
  };

  const handleApprove = async (req: ModerationRequest) => {
    if (processing[req.id]) return;
    setProcessing((p) => ({ ...p, [req.id]: 'approve' }));
    const snapshot = all;
    setStatusOptimistic(req.id, 'approved');

    try {
      await moderationApi.approve(req.id);
      toast.success(`«${req.title_ru}» добавлен в каталог`);
    } catch {
      setAll(snapshot);
      toast.error('Не удалось одобрить заявку');
    } finally {
      setProcessing((p) => {
        const n = { ...p };
        delete n[req.id];
        return n;
      });
    }
  };

  const handleReject = async (req: ModerationRequest) => {
    if (processing[req.id]) return;
    const reason = (rejectDraft[req.id] ?? '').trim();
    if (!reason) {
      toast.error('Укажите причину отклонения');
      return;
    }
    setProcessing((p) => ({ ...p, [req.id]: 'reject' }));
    const snapshot = all;
    setStatusOptimistic(req.id, 'rejected');
    setRejectOpenId(null);

    try {
      await moderationApi.reject(req.id, reason);
      toast.success(`«${req.title_ru}» отклонён`);
      setRejectDraft((d) => {
        const n = { ...d };
        delete n[req.id];
        return n;
      });
    } catch {
      setAll(snapshot);
      setRejectOpenId(req.id);
      toast.error('Не удалось отклонить заявку');
    } finally {
      setProcessing((p) => {
        const n = { ...p };
        delete n[req.id];
        return n;
      });
    }
  };

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
              <ChevronLeftIcon className="w-3.5 h-3.5 transition-transform group-hover:-translate-x-0.5" />
              <span>В каталог</span>
            </Link>
            <span className="hidden sm:inline">Модерация · очередь заявок</span>
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
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
                Модерация
              </p>
              <h1 className="font-serif text-[clamp(3rem,12vw,10rem)] leading-[0.82] tracking-[-0.045em]">
                Панель
                <br />
                <span className="italic">модерации</span>
                <span className="text-[var(--accent-yellow)]">.</span>
              </h1>
            </motion.div>

            <motion.div
              className="lg:col-span-4 lg:text-right"
              initial={prefersReduced ? false : { opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.9, delay: 0.1, ease: EASE_OUT }}
            >
              <p className="max-w-xs lg:ml-auto text-base sm:text-lg text-[var(--text-secondary)] leading-relaxed">
                {counts.pending === 0
                  ? 'Все заявки разобраны'
                  : `${counts.pending} ${plural(
                      counts.pending,
                      'заявка',
                      'заявки',
                      'заявок'
                    )} ждёт проверки`}
              </p>
              <button
                onClick={fetchRequests}
                disabled={loading}
                className="group mt-6 inline-flex items-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <span className="w-11 h-11 rounded-full border border-[var(--line)] grid place-items-center transition-colors duration-300 group-hover:border-[var(--text-primary)] group-hover:bg-[var(--text-primary)] group-hover:text-[var(--bg-primary)]">
                  <ArrowPathIcon className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
                </span>
                <span className="font-mono text-[11px] uppercase tracking-[0.2em] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
                  Обновить
                </span>
              </button>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ============ FILTER BAR ============ */}
      <section className="border-b border-[var(--line)] bg-[var(--bg-secondary)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10">
          <div className="flex flex-wrap items-center justify-between gap-x-8 gap-y-2 py-5 lg:py-6">
            <div className="flex flex-wrap items-center gap-x-8 gap-y-2">
              <FilterTab
                active={tab === 'pending'}
                onClick={() => setTab('pending')}
                label="Ожидают"
                count={counts.pending}
                accent="var(--accent-yellow)"
              />
              <FilterTab
                active={tab === 'approved'}
                onClick={() => setTab('approved')}
                label="Одобренные"
                count={counts.approved}
                accent="var(--accent-green)"
              />
              <FilterTab
                active={tab === 'rejected'}
                onClick={() => setTab('rejected')}
                label="Отклонённые"
                count={counts.rejected}
                accent="var(--accent-red)"
              />
            </div>

            <button
              onClick={() => setSort((s) => (s === 'oldest' ? 'newest' : 'oldest'))}
              className="group inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
            >
              <ClockIcon className="w-3.5 h-3.5" />
              <span className="border-b border-transparent group-hover:border-[var(--text-primary)] pb-0.5 transition-colors">
                {sort === 'oldest' ? 'Сначала старые' : 'Сначала новые'}
              </span>
            </button>
          </div>
        </div>
      </section>

      {/* ============ QUEUE ============ */}
      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 py-12 lg:py-16">
        {loading ? (
          <SkeletonList />
        ) : failed ? (
          <FailedState onRetry={fetchRequests} />
        ) : visible.length === 0 ? (
          <EmptyState tab={tab} onRefresh={fetchRequests} />
        ) : (
          <>
            <div className="flex items-center justify-between pb-3 border-b border-[var(--line)]">
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                {tab === 'pending' && 'Очередь на проверку'}
                {tab === 'approved' && 'Архив · одобренные'}
                {tab === 'rejected' && 'Архив · отклонённые'}
              </p>
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                {String(visible.length).padStart(2, '0')}
              </p>
            </div>

            <ul>
              {visible.map((req, i) => (
                <motion.li
                  key={req.id}
                  initial={prefersReduced ? false : { opacity: 0, y: 14 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{
                    duration: 0.55,
                    delay: Math.min(i * 0.04, 0.35),
                    ease: EASE_OUT,
                  }}
                  className="border-b border-[var(--line)]"
                >
                  <RequestRow
                    req={req}
                    index={i}
                    processing={processing[req.id]}
                    rejectOpen={rejectOpenId === req.id}
                    rejectDraft={rejectDraft[req.id] ?? ''}
                    onOpenReject={() => setRejectOpenId(req.id)}
                    onCancelReject={() => setRejectOpenId(null)}
                    onChangeReason={(v) =>
                      setRejectDraft((d) => ({ ...d, [req.id]: v }))
                    }
                    onApprove={() => handleApprove(req)}
                    onReject={() => handleReject(req)}
                    readOnly={tab !== 'pending'}
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

/* ---------- Таб ---------- */

function FilterTab({
  active,
  onClick,
  label,
  count,
  accent,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  count: number;
  accent: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`group relative flex items-baseline gap-2 pb-1.5 transition-colors ${
        active
          ? 'text-[var(--text-primary)]'
          : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)]'
      }`}
    >
      <span
        className="w-1.5 h-1.5 rounded-full mb-0.5 shrink-0"
        style={{ background: accent, opacity: active ? 1 : 0.45 }}
      />
      <span className="font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.2em]">
        {label}
      </span>
      <span className="font-serif italic text-sm tabular-nums opacity-60">
        {count}
      </span>
      {active && (
        <span
          className="absolute -bottom-[1px] left-0 right-0 h-[1.5px]"
          style={{ background: accent }}
        />
      )}
    </button>
  );
}

/* ---------- Строка заявки ---------- */

function RequestRow({
  req,
  index,
  processing,
  rejectOpen,
  rejectDraft,
  onOpenReject,
  onCancelReject,
  onChangeReason,
  onApprove,
  onReject,
  readOnly,
}: {
  req: ModerationRequest;
  index: number;
  processing?: Processing;
  rejectOpen: boolean;
  rejectDraft: string;
  onOpenReject: () => void;
  onCancelReject: () => void;
  onChangeReason: (v: string) => void;
  onApprove: () => void;
  onReject: () => void;
  readOnly: boolean;
}) {
  const accent = TYPE_ACCENTS[req.type?.name_ru ?? ''] ?? 'var(--accent-yellow)';
  const isApproving = processing === 'approve';
  const isRejecting = processing === 'reject';
  const busy = !!processing;
  const author = req.user?.name?.trim() || 'Аноним';

  return (
    <div className={`py-8 lg:py-10 ${readOnly ? 'opacity-70' : ''}`}>
      <div className="grid lg:grid-cols-12 gap-6 lg:gap-10">
        {/* Левый блок: номер + тип */}
        <div className="lg:col-span-2 flex lg:flex-col items-baseline lg:items-start gap-3 lg:gap-4">
          <span className="font-mono text-[10px] tracking-[0.2em] text-[var(--text-muted)]">
            {String(index + 1).padStart(2, '0')}
          </span>
          {req.type && (
            <span className="inline-flex items-center gap-2">
              <span
                className="w-1.5 h-1.5 rounded-full shrink-0"
                style={{ background: accent }}
              />
              <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)]">
                {req.type.name_ru}
              </span>
            </span>
          )}
        </div>

        {/* Центральный блок: контент */}
        <div className="lg:col-span-7 min-w-0">
          <h3 className="font-serif text-2xl sm:text-3xl lg:text-4xl leading-[1.05] tracking-[-0.015em] break-words">
            {req.title_ru}
          </h3>

          {req.title_en && (
            <p className="mt-2 font-serif italic text-base sm:text-lg text-[var(--text-secondary)] tracking-[-0.005em]">
              {req.title_en}
            </p>
          )}

          <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-2 font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)]">
            {req.release_year && (
              <span>
                Год{' '}
                <span className="text-[var(--text-primary)] tabular-nums ml-1">
                  {req.release_year}
                </span>
              </span>
            )}
            <span className="inline-flex items-center gap-1.5">
              <UserIcon className="w-3 h-3" />
              {author}
            </span>
            <span
              className="inline-flex items-center gap-1.5"
              title={new Date(req.created_at).toLocaleString('ru-RU')}
            >
              <CalendarDaysIcon className="w-3 h-3" />
              {formatRelative(req.created_at)}
            </span>
          </div>

          {req.description_ru && (
            <p className="mt-5 max-w-2xl text-sm sm:text-base text-[var(--text-secondary)] leading-relaxed whitespace-pre-line line-clamp-4">
              {req.description_ru}
            </p>
          )}

          <Link
            href={`/catalog?q=${encodeURIComponent(req.title_ru)}`}
            className="group mt-5 inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
          >
            <MagnifyingGlassIcon className="w-3.5 h-3.5" />
            <span className="border-b border-transparent group-hover:border-[var(--text-primary)] pb-0.5 transition-colors">
              Проверить на дубликаты
            </span>
          </Link>

          {/* Инлайн-форма отклонения */}
          {rejectOpen && !readOnly && (
            <motion.div
              initial={prefersReduced ? false : { opacity: 0, y: -6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, ease: EASE_EDITORIAL }}
              className="mt-8 max-w-xl"
            >
              <label
                htmlFor={`reason-${req.id}`}
                className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--accent-red)] block mb-2"
              >
                Причина отклонения
              </label>
              <textarea
                id={`reason-${req.id}`}
                rows={3}
                value={rejectDraft}
                onChange={(e) => onChangeReason(e.target.value)}
                placeholder="Что не так с заявкой?"
                disabled={isRejecting}
                autoFocus
                className="w-full bg-transparent border-0 border-b-2 border-[var(--accent-red)]/40 focus:border-[var(--accent-red)] rounded-none py-2 text-base font-serif text-[var(--text-primary)] placeholder:text-[var(--text-muted)] placeholder:italic resize-none focus:outline-none transition-colors disabled:opacity-60"
              />
              <div className="mt-4 flex items-center gap-6">
                <button
                  onClick={onReject}
                  disabled={isRejecting || !rejectDraft.trim()}
                  className="group inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--accent-red)] border-b border-[var(--accent-red)] pb-0.5 disabled:opacity-40 disabled:cursor-not-allowed transition-opacity"
                >
                  {isRejecting ? 'Отклоняем…' : 'Отклонить'}
                  <ArrowRightIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:translate-x-0.5" />
                </button>
                <button
                  onClick={onCancelReject}
                  disabled={isRejecting}
                  className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-muted)] hover:text-[var(--text-primary)] border-b border-transparent hover:border-[var(--text-primary)] pb-0.5 disabled:opacity-40 transition-colors"
                >
                  Отмена
                </button>
              </div>
            </motion.div>
          )}
        </div>

        {/* Правый блок: действия / статус */}
        <div className="lg:col-span-3 flex lg:justify-end items-start">
          {readOnly ? (
            <div className="inline-flex items-center gap-2">
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{
                  background:
                    req.status === 'approved'
                      ? 'var(--accent-green)'
                      : 'var(--accent-red)',
                }}
              />
              <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)]">
                {req.status === 'approved' ? 'Одобрено' : 'Отклонено'}
              </span>
            </div>
          ) : rejectOpen ? (
            <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--accent-red)]">
              Укажите причину
            </span>
          ) : (
            <div className="flex lg:flex-col items-center lg:items-end gap-6 lg:gap-4">
              <button
                onClick={onApprove}
                disabled={busy}
                className="group inline-flex items-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-primary)] border-b border-transparent group-hover:border-[var(--accent-green)] pb-0.5 transition-colors">
                  {isApproving ? 'Одобряем…' : 'Одобрить'}
                </span>
                {isApproving ? (
                  <ArrowPathIcon className="w-4 h-4 animate-spin text-[var(--accent-green)]" />
                ) : (
                  <CheckCircleIcon className="w-4 h-4 text-[var(--accent-green)] transition-transform duration-500 group-hover:scale-110" />
                )}
              </button>

              <button
                onClick={onOpenReject}
                disabled={busy}
                className="group inline-flex items-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--accent-red)] border-b border-transparent group-hover:border-[var(--accent-red)] pb-0.5 transition-colors">
                  Отклонить
                </span>
                <XCircleIcon className="w-4 h-4 text-[var(--text-muted)] group-hover:text-[var(--accent-red)] transition-colors" />
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ---------- Skeleton ---------- */

function SkeletonList() {
  return (
    <ul>
      {Array.from({ length: 3 }).map((_, i) => (
        <li
          key={i}
          className="grid lg:grid-cols-12 gap-6 lg:gap-10 py-8 lg:py-10 border-b border-[var(--line)] animate-pulse"
        >
          <div className="lg:col-span-2 space-y-2">
            <div className="h-2.5 w-8 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-2.5 w-20 bg-[var(--bg-tertiary)] rounded" />
          </div>
          <div className="lg:col-span-7 space-y-3">
            <div className="h-8 w-2/3 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-4 w-1/3 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-2.5 w-1/2 bg-[var(--bg-tertiary)] rounded mt-6" />
            <div className="h-3 w-full bg-[var(--bg-tertiary)] rounded mt-3" />
            <div className="h-3 w-5/6 bg-[var(--bg-tertiary)] rounded" />
          </div>
          <div className="lg:col-span-3 lg:flex lg:justify-end space-y-2">
            <div className="h-3 w-24 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-3 w-20 bg-[var(--bg-tertiary)] rounded" />
          </div>
        </li>
      ))}
    </ul>
  );
}

/* ---------- Пустое состояние ---------- */

function EmptyState({
  tab,
  onRefresh,
}: {
  tab: Status;
  onRefresh: () => void;
}) {
  const config = {
    pending: {
      accent: 'var(--accent-green)',
      title: 'Все заявки разобраны',
      text: 'Новые появятся здесь, как только пользователи что-то предложат. Заходите позже.',
      showRefresh: true,
    },
    approved: {
      accent: 'var(--accent-green)',
      title: 'Пока ничего не одобрено',
      text: 'Одобренные вами заявки будут храниться здесь.',
      showRefresh: false,
    },
    rejected: {
      accent: 'var(--accent-red)',
      title: 'Нет отклонённых заявок',
      text: 'Здесь появятся заявки, которые вы отклонили.',
      showRefresh: false,
    },
  }[tab];

  return (
    <div className="py-24 lg:py-32 text-center border-y border-[var(--line)]">
      <div className="inline-flex items-center gap-2 mb-6">
        <span
          className="w-1.5 h-1.5 rounded-full"
          style={{ background: config.accent }}
        />
        <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
          {tab === 'pending' && 'Очередь'}
          {tab === 'approved' && 'Архив'}
          {tab === 'rejected' && 'Архив'}
        </p>
      </div>
      <h2 className="font-serif text-4xl sm:text-5xl tracking-[-0.02em] mb-4">
        {config.title}
      </h2>
      <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
        {config.text}
      </p>
      {config.showRefresh && (
        <div className="mt-10 flex justify-center">
          <button
            onClick={onRefresh}
            className="group inline-flex items-center gap-3"
          >
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
              Обновить
            </span>
            <span className="w-10 h-10 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
              <ArrowPathIcon className="w-4 h-4 transition-transform duration-500 group-hover:rotate-180" />
            </span>
          </button>
        </div>
      )}
    </div>
  );
}

/* ---------- Ошибка загрузки ---------- */

function FailedState({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="py-24 lg:py-32 text-center border-y border-[var(--line)]">
      <div className="inline-flex items-center gap-2 mb-6">
        <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-red)]" />
        <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--accent-red)]">
          Ошибка
        </p>
      </div>
      <h2 className="font-serif text-4xl sm:text-5xl tracking-[-0.02em] mb-4">
        Не удалось загрузить заявки
      </h2>
      <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
        Проверьте соединение и попробуйте ещё раз.
      </p>
      <div className="mt-10 flex justify-center">
        <button
          onClick={onRetry}
          className="group inline-flex items-center gap-3"
        >
          <span className="w-11 h-11 rounded-full bg-[var(--text-primary)] text-[var(--bg-primary)] grid place-items-center transition-transform duration-500 group-hover:rotate-[-8deg] group-hover:scale-105">
            <ArrowPathIcon className="w-5 h-5" />
          </span>
          <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-primary)] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
            Повторить
          </span>
        </button>
      </div>
    </div>
  );
}