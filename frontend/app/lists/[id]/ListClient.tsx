'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import Image from 'next/image';
import { resolveMediaUrl } from '@/lib/utils/media-url';
import { motion, useReducedMotion } from 'framer-motion';
import { listsApi, UserList } from '@/lib/api/lists';
import { Media } from '@/lib/api/media';
import toast from 'react-hot-toast';
import {
  FilmIcon,
  LinkIcon,
  TrashIcon,
  ChevronLeftIcon,
  CheckIcon,
  LockClosedIcon,
  GlobeAltIcon,
  ArrowRightIcon,
  ArrowUpRightIcon,
} from '@heroicons/react/24/outline';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

const STAGGER = ['', 'lg:mt-16', 'lg:mt-4', 'lg:mt-24', 'lg:mt-8'];

function plural(n: number, one: string, few: string, many: string) {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return one;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return few;
  return many;
}

export default function ListClient({ id }: { id: number }) {
  const router = useRouter();
  const prefersReduced = useReducedMotion();
  const [list, setList] = useState<UserList | null>(null);
  const [loading, setLoading] = useState(true);
  const [removingMediaId, setRemovingMediaId] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const fetchList = async () => {
      try {
        setLoading(true);
        const data = await listsApi.getById(id);
        setList(data);
      } catch {
        toast.error('Список не найден');
        router.push('/lists');
      } finally {
        setLoading(false);
      }
    };
    if (id) fetchList();
  }, [id, router]);

  const confirmRemove = (media: Media) => {
    const title = media.title_ru ?? 'этот фильм';
    toast(
      (t) => (
        <span className="flex items-center gap-3 text-sm">
          <span className="text-[var(--text-primary)]">Убрать «{title}»?</span>
          <button
            onClick={() => {
              toast.dismiss(t.id);
              removeMedia(media.id);
            }}
            className="font-semibold text-[var(--accent-red)] hover:underline"
          >
            Убрать
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

  const removeMedia = async (mediaId: number) => {
    const snapshot = list;
    setRemovingMediaId(mediaId);
    setList((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        media: prev.media?.filter((m) => m.id !== mediaId),
      };
    });
    try {
      await listsApi.removeMedia(id, mediaId);
      toast.success('Фильм убран из списка');
    } catch {
      setList(snapshot);
      toast.error('Не удалось удалить');
    } finally {
      setRemovingMediaId(null);
    }
  };

  const handleCopyLink = async () => {
    if (!list?.share_token) {
      toast.error('Список не публичный');
      return;
    }
    const link = `${window.location.origin}/public/lists/${list.share_token}`;
    try {
      await navigator.clipboard.writeText(link);
      setCopied(true);
      toast.success('Ссылка скопирована');
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error('Не удалось скопировать ссылку');
    }
  };

  // ===== Loading =====
  if (loading) return <ListSkeleton />;

  // ===== Not found =====
  if (!list) {
    return (
      <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-24 lg:py-32 text-center">
          <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
            Ошибка
          </p>
          <h1 className="font-serif text-4xl sm:text-5xl tracking-[-0.02em] mb-4">
            Список не найден
          </h1>
          <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
            Возможно, он был удалён или у вас нет к нему доступа
          </p>
          <div className="mt-10 flex justify-center">
            <Link href="/lists" className="group inline-flex items-center gap-3">
              <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
                К моим спискам
              </span>
              <span className="w-10 h-10 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
                <ArrowRightIcon className="w-4 h-4 transition-transform duration-500 group-hover:translate-x-0.5" />
              </span>
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const mediaList: Media[] = list.media || [];
  const count = mediaList.length;

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      {/* ============ MASTHEAD ============ */}
      <section className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
            <Link
              href="/lists"
              className="group inline-flex items-center gap-2 hover:text-[var(--text-primary)] transition-colors"
            >
              <ChevronLeftIcon className="w-3.5 h-3.5 transition-transform group-hover:-translate-x-0.5" />
              <span>Мои списки</span>
            </Link>
            <span className="hidden sm:inline">
              Подборка · {count} {plural(count, 'фильм', 'фильма', 'фильмов')}
            </span>
          </div>
        </div>

        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-14 lg:pb-20">
          <motion.header
            initial={prefersReduced ? false : { opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, ease: EASE_OUT }}
          >
            <div className="flex items-center gap-3 mb-6">
              {list.is_public ? (
                <span className="inline-flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-green)]" />
                  <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)]">
                    Публичный
                  </span>
                </span>
              ) : (
                <span className="inline-flex items-center gap-2">
                  <LockClosedIcon className="w-3 h-3 text-[var(--text-muted)]" />
                  <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                    Приватный
                  </span>
                </span>
              )}
              <span className="text-[var(--text-muted)]">·</span>
              <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                {count} {plural(count, 'фильм', 'фильма', 'фильмов')}
              </span>
            </div>

            <h1 className="font-serif text-[clamp(3rem,11vw,9rem)] leading-[0.85] tracking-[-0.04em] break-words">
              {list.name}
              <span className="text-[var(--accent-yellow)]">.</span>
            </h1>

            {list.description && (
              <p className="mt-8 max-w-2xl text-base sm:text-lg text-[var(--text-secondary)] leading-relaxed">
                {list.description}
              </p>
            )}

            <div className="mt-10 flex flex-wrap items-center gap-x-8 gap-y-4">
              {list.is_public && list.share_token && (
                <button
                  onClick={handleCopyLink}
                  className="group inline-flex items-center gap-3"
                >
                  <span className="w-11 h-11 rounded-full border border-[var(--line)] grid place-items-center transition-colors duration-300 group-hover:border-[var(--text-primary)] group-hover:bg-[var(--text-primary)] group-hover:text-[var(--bg-primary)]">
                    {copied ? (
                      <CheckIcon className="w-5 h-5" />
                    ) : (
                      <LinkIcon className="w-5 h-5" />
                    )}
                  </span>
                  <span className="font-mono text-[11px] uppercase tracking-[0.2em] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
                    {copied ? 'Скопировано' : 'Поделиться'}
                  </span>
                </button>
              )}
              <Link
                href={`/catalog?add_to_list=${id}`}
                className="group inline-flex items-center gap-3"
              >
                <span className="w-11 h-11 rounded-full bg-[var(--text-primary)] text-[var(--bg-primary)] grid place-items-center transition-transform duration-500 group-hover:rotate-[-8deg] group-hover:scale-105">
                  <ArrowRightIcon className="w-5 h-5" />
                </span>
                <span className="font-mono text-[11px] uppercase tracking-[0.2em] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
                  Добавить фильм
                </span>
              </Link>
            </div>
          </motion.header>
        </div>
      </section>

      {/* ============ MEDIA GRID ============ */}
      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
        {count === 0 ? (
          <EmptyList />
        ) : (
          <>
            <div className="flex items-center justify-between pb-3 border-b border-[var(--line)] mb-8 lg:mb-10">
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                Содержимое подборки
              </p>
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                {String(count).padStart(2, '0')}
              </p>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4 lg:gap-x-5 lg:gap-y-0 items-start">
              {mediaList.map((media, i) => (
                <motion.div
                  key={media.id}
                  initial={prefersReduced ? false : { opacity: 0, y: 14 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{
                    duration: 0.6,
                    delay: Math.min(i * 0.04, 0.4),
                    ease: EASE_OUT,
                  }}
                  className={STAGGER[i % 5]}
                >
                  <MediaCard
                    media={media}
                    index={i}
                    onRemove={() => confirmRemove(media)}
                    removing={removingMediaId === media.id}
                  />
                </motion.div>
              ))}
            </div>
          </>
        )}
      </section>
    </div>
  );
}

/* ---------- Карточка фильма ---------- */

function MediaCard({
  media,
  index,
  onRemove,
  removing,
}: {
  media: Media;
  index: number;
  onRemove: () => void;
  removing: boolean;
}) {
  const year = media.release_date
    ? new Date(media.release_date).getFullYear()
    : null;

  return (
    <div className="relative group">
      <Link href={`/media/${media.id}`} className="block">
        <div className="relative aspect-[2/3] overflow-hidden rounded-[2px] bg-[var(--bg-tertiary)]">
          {media.poster_url ? (
            <Image
              src={resolveMediaUrl(media.poster_url)!}
              alt=""
              fill
              sizes="(max-width: 768px) 160px, 240px"
              className="object-cover transition-transform duration-[1400ms] ease-[cubic-bezier(0.76,0,0.24,1)] group-hover:scale-[1.08]"
            />
          ) : (
            <div className="w-full h-full grid place-items-center text-[var(--text-muted)]">
              <FilmIcon className="w-10 h-10 opacity-30" />
            </div>
          )}

          {/* Градиент на hover */}
          <span className="pointer-events-none absolute inset-0 bg-gradient-to-t from-black/85 via-black/0 to-black/0 opacity-0 group-hover:opacity-100 transition-opacity duration-700" />

          {/* Тонкая золотая рамка */}
          <span className="pointer-events-none absolute inset-2 border border-transparent group-hover:border-[var(--accent-yellow)]/70 transition-colors duration-700" />

          {/* Порядковый номер */}
          <span className="absolute top-3 left-3 font-mono text-[10px] tracking-[0.15em] text-white/60 mix-blend-difference opacity-0 group-hover:opacity-100 transition-opacity duration-500">
            {String(index + 1).padStart(2, '0')}
          </span>

          {/* Тип */}
          {media.type && (
            <span className="absolute top-3 right-3 font-mono text-[9px] uppercase tracking-[0.15em] text-white/80 opacity-0 group-hover:opacity-100 transition-opacity duration-500">
              {media.type.name_ru}
            </span>
          )}

          {/* Стрелка снизу */}
          <span className="absolute bottom-3 right-3 w-8 h-8 grid place-items-center bg-black/60 backdrop-blur-sm text-white opacity-0 translate-y-2 group-hover:opacity-100 group-hover:translate-y-0 transition-all duration-500">
            <ArrowUpRightIcon className="w-3.5 h-3.5" />
          </span>
        </div>

        <div className="mt-4">
          <h3 className="font-serif text-base lg:text-lg leading-snug line-clamp-2 group-hover:italic transition-[font-style] duration-300">
            {media.title_ru}
          </h3>
          <div className="mt-1.5 flex items-baseline gap-1.5 text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] min-w-0">
            {year && <span className="tabular-nums shrink-0">{year}</span>}
            {year && media.title_en && <span className="shrink-0">·</span>}
            {media.title_en && <span className="truncate">{media.title_en}</span>}
          </div>
        </div>
      </Link>

      <button
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          onRemove();
        }}
        disabled={removing}
        aria-label="Убрать из списка"
        title="Убрать из списка"
        className="absolute top-3 right-3 w-8 h-8 flex items-center justify-center text-white opacity-0 group-hover:opacity-100 focus-visible:opacity-100 hover:text-[var(--accent-red)] transition-all disabled:opacity-50"
      >
        {removing ? (
          <div className="w-4 h-4 border-2 border-white/60 border-t-transparent rounded-full animate-spin" />
        ) : (
          <TrashIcon className="w-4 h-4" />
        )}
      </button>
    </div>
  );
}

/* ---------- Пустое состояние ---------- */

function EmptyList() {
  return (
    <div className="py-24 lg:py-32 text-center border-y border-[var(--line)]">
      <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
        Пусто
      </p>
      <h2 className="font-serif text-4xl sm:text-5xl tracking-[-0.02em] mb-4">
        В подборке пока пусто
      </h2>
      <p className="text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
        Найдите фильмы в каталоге и добавьте их сюда — соберите свой идеальный список.
      </p>
      <div className="mt-10 flex justify-center">
        <Link href="/catalog" className="group inline-flex items-center gap-3">
          <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
            Перейти в каталог
          </span>
          <span className="w-10 h-10 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
            <ArrowRightIcon className="w-4 h-4 transition-transform duration-500 group-hover:translate-x-0.5" />
          </span>
        </Link>
      </div>
    </div>
  );
}

/* ---------- Skeleton ---------- */

function ListSkeleton() {
  return (
    <div className="min-h-screen bg-[var(--bg-primary)]">
      <section className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] animate-pulse">
            <div className="h-2.5 w-24 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-2.5 w-32 bg-[var(--bg-tertiary)] rounded" />
          </div>
        </div>
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-14 lg:pb-20 animate-pulse">
          <div className="h-3 w-32 bg-[var(--bg-tertiary)] rounded mb-6" />
          <div className="h-24 w-3/4 max-w-2xl bg-[var(--bg-tertiary)] rounded" />
          <div className="h-4 w-1/3 max-w-md bg-[var(--bg-tertiary)] rounded mt-8" />
        </div>
      </section>
      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4 lg:gap-x-5 lg:gap-y-0 items-start animate-pulse">
          {Array.from({ length: 10 }).map((_, i) => (
            <div key={i} className={STAGGER[i % 5]}>
              <div className="aspect-[2/3] rounded-[2px] bg-[var(--bg-tertiary)]" />
              <div className="h-4 w-4/5 bg-[var(--bg-tertiary)] rounded mt-4" />
              <div className="h-2.5 w-1/3 bg-[var(--bg-tertiary)] rounded mt-2" />
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}