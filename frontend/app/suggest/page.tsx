'use client';

import { useMemo, useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { useGenres } from '@/hooks/useReferences';
import Link from 'next/link';
import { motion, useReducedMotion } from 'framer-motion';
import { moderationApi } from '@/lib/api/moderation';
import { referenceApi, Genre } from '@/lib/api/reference';
import toast from 'react-hot-toast';
import { tmdbApi, TmdbMovie } from '@/lib/api/tmdb';
import {
  CheckCircleIcon,
  ChevronLeftIcon,
  ArrowPathIcon,
  ShieldCheckIcon,
  ClockIcon,
  SparklesIcon,
  CheckIcon,
  MagnifyingGlassIcon,
  PlusCircleIcon,
  InformationCircleIcon,
  FilmIcon,
  XMarkIcon,
  ChevronDownIcon,
  ArrowRightIcon,
  ExclamationCircleIcon,
} from '@heroicons/react/24/outline';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const EASE_EDITORIAL = [0.76, 0, 0.24, 1] as const;

const TYPES = [
  { id: 1, name: 'Фильм' },
  { id: 2, name: 'Сериал' },
  { id: 3, name: 'Аниме' },
  { id: 4, name: 'Мультфильм' },
];

const DESC_MAX = 2000;
const YEAR_MIN = 1888;
const YEAR_MAX = new Date().getFullYear() + 2;
const MAX_FILE_SIZE = 5 * 1024 * 1024;

const INITIAL = {
  title_ru: '',
  title_en: '',
  type_id: 1,
  release_year: '',
  description_ru: '',
  poster: null as File | null,
};

function editorialInputClass(error?: boolean) {
  return `w-full bg-transparent border-0 border-b ${
    error ? 'border-[var(--accent-red)]' : 'border-[var(--line)]'
  } rounded-none px-0 py-3 text-lg sm:text-xl font-serif tracking-[-0.005em] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] placeholder:italic placeholder:opacity-60 focus:outline-none ${
    error ? 'focus:border-[var(--accent-red)]' : 'focus:border-[var(--accent-yellow)]'
  } transition-colors disabled:opacity-50`;
}

export default function SuggestPage() {
  const router = useRouter();
  const prefersReduced = useReducedMotion();
  const [selectedGenreIds, setSelectedGenreIds] = useState<number[]>([]);
  const [isGenreDropdownOpen, setIsGenreDropdownOpen] = useState(false);

  const [status, setStatus] = useState<'idle' | 'submitting' | 'success'>('idle');
  const [formData, setFormData] = useState(INITIAL);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [posterPreview, setPosterPreview] = useState<string | null>(null);
  const [tmdbQuery, setTmdbQuery] = useState('');
  const [tmdbDetails, setTmdbDetails] = useState<any>(null);
  const [tmdbResults, setTmdbResults] = useState<TmdbMovie[]>([]);
  const [isTmdbSearching, setIsTmdbSearching] = useState(false);
  const [isTmdbDropdownOpen, setIsTmdbDropdownOpen] = useState(false);
  const tmdbWrapperRef = useRef<HTMLDivElement>(null);

  const { data: genres, isLoading: genresLoading, error: genresError } = useGenres();

  useEffect(() => {
    if (!isGenreDropdownOpen) return;
    const handleClickOutside = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest('.genre-dropdown')) {
        setIsGenreDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isGenreDropdownOpen]);

  useEffect(() => {
    if (tmdbQuery.trim().length < 2) {
      setTmdbResults([]);
      setIsTmdbDropdownOpen(false);
      return;
    }

    setIsTmdbSearching(true);
    const timer = setTimeout(async () => {
      try {
        const results = await tmdbApi.search(tmdbQuery);
        setTmdbResults(results);
        setIsTmdbDropdownOpen(true);
      } catch (error) {
        console.error('Ошибка поиска TMDB:', error);
      } finally {
        setIsTmdbSearching(false);
      }
    }, 400);

    return () => clearTimeout(timer);
  }, [tmdbQuery]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (tmdbWrapperRef.current && !tmdbWrapperRef.current.contains(event.target as Node)) {
        setIsTmdbDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleTmdbSelect = async (movie: TmdbMovie) => {
    update('title_ru', movie.title_ru);
    update('title_en', movie.title_en || '');
    update('release_year', movie.release_date ? movie.release_date.split('-')[0] : '');
    update('description_ru', movie.overview || '');

    if (movie.poster_url) {
      try {
        const response = await fetch(movie.poster_url);
        const blob = await response.blob();
        const file = new File([blob], `poster_${movie.tmdb_id}.jpg`, { type: 'image/jpeg' });

        update('poster', file);
        if (posterPreview) URL.revokeObjectURL(posterPreview);
        setPosterPreview(URL.createObjectURL(file));
      } catch (e) {
        console.error('Не удалось загрузить постер автоматически:', e);
        toast.error('Данные заполнены, но постер придется загрузить вручную');
      }
    }

    if (movie.tmdb_id) {
      try {
        const details = await tmdbApi.getDetails(movie.tmdb_id);
        setTmdbDetails(details);
      } catch (e) {
        console.error('Не удалось загрузить детали TMDB:', e);
      }
    }

    setTmdbQuery('');
    setTmdbResults([]);
    setIsTmdbDropdownOpen(false);
    toast.success(`Данные фильма «${movie.title_ru}» автоматически заполнены!`);
  };

  const isDirty = useMemo(
    () => JSON.stringify(formData) !== JSON.stringify(INITIAL),
    [formData]
  );

  const update = <K extends keyof typeof INITIAL>(
    key: K,
    value: (typeof INITIAL)[K]
  ) => {
    setFormData((prev) => ({ ...prev, [key]: value }));
    if (errors[key]) {
      setErrors((prev) => {
        const next = { ...prev };
        delete next[key as string];
        return next;
      });
    }
  };

  const validate = () => {
    const next: Record<string, string> = {};
    const ru = formData.title_ru.trim();
    if (!ru) next.title_ru = 'Укажите название';
    else if (ru.length > 200) next.title_ru = 'Не более 200 символов';

    if (formData.title_en.length > 200) {
      next.title_en = 'Не более 200 символов';
    }

    if (formData.release_year) {
      if (!/^\d{4}$/.test(formData.release_year)) {
        next.release_year = 'Год — 4 цифры';
      } else {
        const y = Number(formData.release_year);
        if (y < YEAR_MIN || y > YEAR_MAX) {
          next.release_year = `От ${YEAR_MIN} до ${YEAR_MAX}`;
        }
      }
    }

    if (formData.description_ru.length > DESC_MAX) {
      next.description_ru = `Не более ${DESC_MAX} символов`;
    }

    if (formData.poster && formData.poster.size > MAX_FILE_SIZE) {
      next.poster = 'Файл слишком большой (макс. 5 МБ)';
    }

    setErrors(next);
    return Object.keys(next).length === 0;
  };

  const handlePosterChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (file.size > MAX_FILE_SIZE) {
        toast.error('Файл слишком большой (макс. 5 МБ)');
        e.target.value = '';
        return;
      }

      const validTypes = ['image/jpeg', 'image/png', 'image/webp'];
      if (!validTypes.includes(file.type)) {
        toast.error('Разрешены только JPG, PNG и WebP');
        e.target.value = '';
        return;
      }

      update('poster', file);

      if (posterPreview) {
        URL.revokeObjectURL(posterPreview);
      }
      setPosterPreview(URL.createObjectURL(file));
    }
  };

  const clearPoster = () => {
    update('poster', null);
    setPosterPreview(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) {
      toast.error('Проверьте заполнение формы');
      return;
    }
    setStatus('submitting');
    try {
      const dataToSend = new FormData();
      dataToSend.append('title_ru', formData.title_ru.trim());
      if (formData.title_en.trim()) dataToSend.append('title_en', formData.title_en.trim());
      dataToSend.append('type_id', String(formData.type_id));
      if (formData.release_year) dataToSend.append('release_year', formData.release_year);
      if (formData.description_ru.trim()) dataToSend.append('description_ru', formData.description_ru.trim());
      if (formData.poster) dataToSend.append('poster', formData.poster);

      if (tmdbDetails) {
        const tmdbPayload = {
          director: tmdbDetails.director || null,
          cast: tmdbDetails.cast || [],
          companies: tmdbDetails.companies || [],
        };
        dataToSend.append('tmdb_data', JSON.stringify(tmdbPayload));
      }

      selectedGenreIds.forEach((genreId) => {
        dataToSend.append('genre_ids[]', String(genreId));
      });

      await moderationApi.submit(dataToSend);
      setStatus('success');
    } catch (error: any) {
      setStatus('idle');
      const msg = error?.response?.data?.message ?? 'Ошибка отправки. Попробуйте позже';
      toast.error(msg);
    }
  };

  const handleCancel = () => {
    if (isDirty && !confirm('Отменить заполнение? Введённые данные будут потеряны.')) {
      return;
    }
    if (typeof window !== 'undefined' && window.history.length > 1) {
      router.back();
    } else {
      router.push('/');
    }
  };

  if (status === 'success') {
    return (
      <SuccessState
        titleRu={formData.title_ru}
        onAnother={() => {
          setFormData(INITIAL);
          setErrors({});
          setPosterPreview(null);
          setStatus('idle');
        }}
      />
    );
  }

  const submitting = status === 'submitting';
  const yearNow = new Date().getFullYear();

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
              <span>На главную</span>
            </Link>
            <span className="hidden sm:inline">Модерация · Заявка</span>
          </div>
        </div>

        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-14 lg:pb-20">
          <motion.div
            initial={prefersReduced ? false : { opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 1, ease: EASE_OUT }}
          >
            <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
              Модерация
            </p>
            <h1 className="font-serif text-[clamp(2.75rem,10vw,8rem)] leading-[0.84] tracking-[-0.045em]">
              Предложить
              <br />
              <span className="italic">фильм</span>
              <span className="text-[var(--accent-yellow)]">.</span>
            </h1>
            <p className="mt-8 max-w-xl text-base sm:text-lg text-[var(--text-secondary)] leading-relaxed">
              Если чего-то не хватает в каталоге — расскажите нам. Заявка попадёт
              к модераторам, и после проверки фильм появится в общем каталоге.
            </p>
          </motion.div>
        </div>
      </section>

      {/* ============ FORM ============ */}
      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
        <div className="grid lg:grid-cols-12 gap-12 lg:gap-16">
          {/* Left — form */}
          <motion.div
            className="lg:col-span-8 min-w-0"
            initial={prefersReduced ? false : { opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, ease: EASE_OUT }}
          >
            <form onSubmit={handleSubmit} className="space-y-12" noValidate>
              {/* ===== TMDB ===== */}
              <div>
                <div className="flex items-center justify-between pb-3 border-b border-[var(--line)] mb-6">
                  <div className="flex items-center gap-2">
                    <SparklesIcon className="w-3.5 h-3.5 text-[var(--accent-yellow)]" />
                    <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-secondary)]">
                      Умный поиск (TMDB)
                    </span>
                  </div>
                  <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                    Автозаполнение
                  </span>
                </div>

                <div className="relative" ref={tmdbWrapperRef}>
                  <div className="relative">
                    <MagnifyingGlassIcon className="absolute left-0 top-1/2 -translate-y-1/2 w-5 h-5 text-[var(--text-muted)]" />
                    <input
                      type="text"
                      value={tmdbQuery}
                      onChange={(e) => setTmdbQuery(e.target.value)}
                      onFocus={() => tmdbQuery.trim().length >= 2 && setIsTmdbDropdownOpen(true)}
                      placeholder="Начните вводить название (например, Дюна)…"
                      className="w-full bg-transparent border-0 border-b border-[var(--line)] rounded-none pl-8 pr-10 py-3 text-lg sm:text-xl font-serif text-[var(--text-primary)] placeholder:text-[var(--text-muted)] placeholder:italic placeholder:opacity-60 focus:outline-none focus:border-[var(--accent-yellow)] transition-colors disabled:opacity-50"
                      disabled={submitting}
                    />
                    {tmdbQuery && (
                      <button
                        type="button"
                        onClick={() => {
                          setTmdbQuery('');
                          setTmdbResults([]);
                        }}
                        className="absolute right-0 top-1/2 -translate-y-1/2 text-[var(--text-muted)] hover:text-[var(--text-primary)] p-2"
                      >
                        <XMarkIcon className="w-4 h-4" />
                      </button>
                    )}
                  </div>

                  {isTmdbDropdownOpen && (tmdbQuery.trim().length >= 2 || isTmdbSearching) && (
                    <div className="absolute top-full left-0 right-0 mt-3 bg-[var(--bg-primary)] border border-[var(--line)] z-30 overflow-hidden max-h-80 overflow-y-auto">
                      {isTmdbSearching ? (
                        <div className="p-5 text-center font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                          Ищем в базе TMDB…
                        </div>
                      ) : tmdbResults.length === 0 ? (
                        <div className="p-5 text-center font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                          Ничего не найдено
                        </div>
                      ) : (
                        <ul>
                          {tmdbResults.map((movie) => (
                            <li key={movie.tmdb_id} className="border-b border-[var(--line)] last:border-0">
                              <button
                                type="button"
                                onClick={() => handleTmdbSelect(movie)}
                                className="group w-full flex items-center gap-4 p-3 text-left hover:bg-[var(--bg-secondary)] transition-colors"
                              >
                                <div className="w-10 h-14 overflow-hidden bg-[var(--bg-tertiary)] shrink-0">
                                  {movie.poster_url ? (
                                    <img
                                      src={movie.poster_url}
                                      alt=""
                                      className="w-full h-full object-cover"
                                    />
                                  ) : (
                                    <div className="w-full h-full grid place-items-center">
                                      <FilmIcon className="w-4 h-4 text-[var(--text-muted)] opacity-50" />
                                    </div>
                                  )}
                                </div>
                                <div className="flex-1 min-w-0">
                                  <p className="font-serif text-base text-[var(--text-primary)] truncate leading-tight">
                                    {movie.title_ru}
                                  </p>
                                  <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)] truncate">
                                    {movie.title_en && <>{movie.title_en} · </>}
                                    {movie.release_date
                                      ? new Date(movie.release_date).getFullYear()
                                      : 'Год неизвестен'}
                                    {movie.vote_average ? ` · ★ ${movie.vote_average}` : ''}
                                  </p>
                                </div>
                                <ArrowRightIcon className="w-4 h-4 text-[var(--text-muted)] group-hover:text-[var(--accent-yellow)] transition-colors shrink-0" />
                              </button>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}
                </div>

                <p className="mt-4 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)] flex items-center gap-2">
                  <InformationCircleIcon className="w-3 h-3" />
                  Выберите фильм — данные заполнятся автоматически
                </p>
              </div>

              {/* ===== Разделитель ===== */}
              <div className="flex items-center gap-4">
                <span className="h-px flex-1 bg-[var(--line)]" />
                <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                  Или вручную
                </span>
                <span className="h-px flex-1 bg-[var(--line)]" />
              </div>

              {/* ===== Основные поля ===== */}
              <div className="grid gap-10">
                <EditorialField label="Название на русском" htmlFor="title_ru" required error={errors.title_ru}>
                  <input
                    id="title_ru"
                    type="text"
                    value={formData.title_ru}
                    onChange={(e) => update('title_ru', e.target.value)}
                    disabled={submitting}
                    placeholder="Например, Интерстеллар"
                    maxLength={200}
                    className={editorialInputClass(!!errors.title_ru)}
                  />
                </EditorialField>

                <EditorialField
                  label="Оригинальное название"
                  htmlFor="title_en"
                  hint="Необязательно"
                  error={errors.title_en}
                >
                  <input
                    id="title_en"
                    type="text"
                    value={formData.title_en}
                    onChange={(e) => update('title_en', e.target.value)}
                    disabled={submitting}
                    placeholder="Interstellar"
                    maxLength={200}
                    className={editorialInputClass(!!errors.title_en)}
                  />
                </EditorialField>

                <div className="grid sm:grid-cols-2 gap-10">
                  <div>
                    <label
                      htmlFor="type_id"
                      className="block font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] mb-1"
                    >
                      Тип<span className="ml-0.5 text-[var(--accent-red)]">*</span>
                    </label>
                    <select
                      id="type_id"
                      value={formData.type_id}
                      onChange={(e) => update('type_id', Number(e.target.value))}
                      disabled={submitting}
                      className="w-full bg-transparent border-0 border-b border-[var(--line)] rounded-none px-0 py-3 text-lg sm:text-xl font-serif text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-yellow)] cursor-pointer appearance-none transition-colors disabled:opacity-50"
                    >
                      {TYPES.map((t) => (
                        <option key={t.id} value={t.id}>
                          {t.name}
                        </option>
                      ))}
                    </select>
                  </div>

                  <EditorialField
                    label="Год выпуска"
                    htmlFor="release_year"
                    hint="Необязательно"
                    error={errors.release_year}
                  >
                    <input
                      id="release_year"
                      type="text"
                      inputMode="numeric"
                      value={formData.release_year}
                      onChange={(e) =>
                        update('release_year', e.target.value.replace(/\D/g, '').slice(0, 4))
                      }
                      disabled={submitting}
                      placeholder={String(yearNow)}
                      className={editorialInputClass(!!errors.release_year)}
                    />
                  </EditorialField>
                </div>

                <div>
                  <div className="flex items-baseline justify-between mb-1">
                    <label
                      htmlFor="description_ru"
                      className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]"
                    >
                      Описание
                    </label>
                    <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)] tabular-nums">
                      {formData.description_ru.length} / {DESC_MAX}
                    </span>
                  </div>
                  <textarea
                    id="description_ru"
                    rows={5}
                    value={formData.description_ru}
                    onChange={(e) => update('description_ru', e.target.value)}
                    disabled={submitting}
                    placeholder="Коротко о чём фильм — 2–3 предложения"
                    maxLength={DESC_MAX}
                    className={`${editorialInputClass(!!errors.description_ru)} resize-none`}
                  />
                  {errors.description_ru && (
                    <p className="mt-2 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--accent-red)]">
                      {errors.description_ru}
                    </p>
                  )}
                </div>

                {/* Жанры */}
                <div>
                  <div className="flex items-baseline justify-between mb-1">
                    <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                      Жанры
                    </span>
                    <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)]">
                      Необязательно
                    </span>
                  </div>

                  <div className="relative genre-dropdown">
                    <button
                      type="button"
                      onClick={() => setIsGenreDropdownOpen(!isGenreDropdownOpen)}
                      className="w-full flex items-center justify-between bg-transparent border-0 border-b border-[var(--line)] rounded-none px-0 py-3 text-lg font-serif text-[var(--text-primary)] hover:border-[var(--accent-yellow)] transition-colors"
                    >
                      <span className="truncate">
                        {selectedGenreIds.length > 0
                          ? `Выбрано жанров: ${selectedGenreIds.length}`
                          : 'Выберите жанры'}
                      </span>
                      <ChevronDownIcon
                        className={`w-4 h-4 text-[var(--text-muted)] transition-transform duration-500 ${
                          isGenreDropdownOpen ? 'rotate-180' : ''
                        }`}
                      />
                    </button>

                    {isGenreDropdownOpen && (
                      <div className="absolute top-full left-0 right-0 mt-3 bg-[var(--bg-primary)] border border-[var(--line)] z-20 p-2 max-h-56 overflow-y-auto">
                        {genres.map((genre) => {
                          const isSelected = selectedGenreIds.includes(genre.id);
                          return (
                            <label
                              key={genre.id}
                              className="group flex items-center gap-3 p-2 cursor-pointer hover:bg-[var(--bg-secondary)] transition-colors"
                            >
                              <span
                                className={`w-3.5 h-3.5 border transition-colors grid place-items-center shrink-0 ${
                                  isSelected
                                    ? 'bg-[var(--accent-yellow)] border-[var(--accent-yellow)]'
                                    : 'border-[var(--line)] group-hover:border-[var(--text-primary)]'
                                }`}
                              >
                                {isSelected && <span className="w-1.5 h-1.5 bg-black" />}
                              </span>
                              <input
                                type="checkbox"
                                checked={isSelected}
                                onChange={(e) => {
                                  if (e.target.checked) {
                                    setSelectedGenreIds([...selectedGenreIds, genre.id]);
                                  } else {
                                    setSelectedGenreIds(
                                      selectedGenreIds.filter((id) => id !== genre.id)
                                    );
                                  }
                                }}
                                className="sr-only"
                              />
                              <span className="text-sm text-[var(--text-primary)]">
                                {genre.name_ru}
                              </span>
                            </label>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  {selectedGenreIds.length > 0 && (
                    <div className="flex flex-wrap gap-2 mt-4">
                      {selectedGenreIds.map((genreId) => {
                        const genre = genres.find((g) => g.id === genreId);
                        return (
                          <span
                            key={genreId}
                            className="inline-flex items-center gap-2 px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-secondary)] border border-[var(--line)]"
                          >
                            {genre?.name_ru}
                            <button
                              type="button"
                              onClick={() =>
                                setSelectedGenreIds(
                                  selectedGenreIds.filter((id) => id !== genreId)
                                )
                              }
                              className="text-[var(--text-muted)] hover:text-[var(--accent-red)] transition-colors"
                            >
                              <XMarkIcon className="w-3 h-3" />
                            </button>
                          </span>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Постер */}
                <div>
                  <div className="flex items-baseline justify-between mb-3">
                    <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
                      Постер
                    </span>
                    <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)]">
                      JPG · PNG · WebP · 5 МБ
                    </span>
                  </div>

                  <div className="flex items-start gap-6">
                    {posterPreview ? (
                      <div className="relative shrink-0">
                        <img
                          src={posterPreview}
                          alt="Превью постера"
                          className="w-24 h-36 object-cover bg-[var(--bg-tertiary)]"
                        />
                        <button
                          type="button"
                          onClick={clearPoster}
                          disabled={submitting}
                          className="absolute -top-2 -right-2 w-6 h-6 bg-[var(--accent-red)] text-white grid place-items-center hover:scale-110 transition-transform disabled:opacity-60"
                          aria-label="Удалить постер"
                        >
                          <XMarkIcon className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ) : (
                      <div className="w-24 h-36 border border-dashed border-[var(--line)] bg-[var(--bg-tertiary)] grid place-items-center shrink-0">
                        <FilmIcon className="w-8 h-8 text-[var(--text-muted)] opacity-50" />
                      </div>
                    )}

                    <div className="flex-1 min-w-0">
                      <label
                        htmlFor="poster"
                        className="inline-flex items-center gap-2 cursor-pointer font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)] border-b border-[var(--line)] hover:border-[var(--text-primary)] pb-0.5 transition-colors"
                      >
                        Выбрать файл
                      </label>
                      <input
                        id="poster"
                        type="file"
                        accept="image/jpeg,image/png,image/webp"
                        onChange={handlePosterChange}
                        disabled={submitting}
                        className="sr-only"
                      />
                      {errors.poster && (
                        <p className="mt-3 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--accent-red)]">
                          {errors.poster}
                        </p>
                      )}
                    </div>
                  </div>
                </div>

                {/* TMDB details */}
                {tmdbDetails && (
                  <div className="border-t border-[var(--line)] pt-8">
                    <div className="flex items-center gap-2 mb-4">
                      <SparklesIcon className="w-3.5 h-3.5 text-[var(--accent-yellow)]" />
                      <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-secondary)]">
                        Данные из TMDB
                      </span>
                    </div>

                    <dl className="grid gap-4">
                      {tmdbDetails.director && (
                        <div className="grid grid-cols-[120px_1fr] gap-4 border-b border-[var(--line)] pb-3">
                          <dt className="font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)]">
                            Режиссёр
                          </dt>
                          <dd className="font-serif text-base text-[var(--text-primary)]">
                            {tmdbDetails.director.name}
                          </dd>
                        </div>
                      )}
                      {tmdbDetails.companies.length > 0 && (
                        <div className="grid grid-cols-[120px_1fr] gap-4 border-b border-[var(--line)] pb-3">
                          <dt className="font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)]">
                            Студии
                          </dt>
                          <dd className="font-serif text-base text-[var(--text-primary)]">
                            {tmdbDetails.companies.map((c: any) => c.name).join(', ')}
                          </dd>
                        </div>
                      )}
                      {tmdbDetails.cast.length > 0 && (
                        <div className="grid grid-cols-[120px_1fr] gap-4">
                          <dt className="font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)]">
                            В ролях
                          </dt>
                          <dd className="flex flex-wrap gap-x-4 gap-y-2">
                            {tmdbDetails.cast.map((actor: any) => (
                              <span
                                key={actor.tmdb_id}
                                className="font-serif text-sm text-[var(--text-primary)]"
                              >
                                {actor.name}
                                {actor.character && (
                                  <span className="text-[var(--text-muted)]">
                                    {' '}
                                    <span className="italic">— {actor.character}</span>
                                  </span>
                                )}
                              </span>
                            ))}
                          </dd>
                        </div>
                      )}
                    </dl>
                  </div>
                )}
              </div>

              {/* Actions */}
              <div className="flex flex-col-reverse sm:flex-row sm:items-center sm:justify-between gap-4 pt-8 border-t border-[var(--line)]">
                <button
                  type="button"
                  onClick={handleCancel}
                  disabled={submitting}
                  className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-muted)] hover:text-[var(--text-primary)] border-b border-transparent hover:border-[var(--text-primary)] pb-0.5 transition-colors self-start sm:self-auto disabled:opacity-40"
                >
                  Отмена
                </button>

                <button
                  type="submit"
                  disabled={submitting}
                  className="group inline-flex items-center justify-between gap-6 sm:gap-10 px-0 sm:px-2 py-4 border-y-2 border-[var(--text-primary)] text-[var(--text-primary)] hover:bg-[var(--text-primary)] hover:text-[var(--bg-primary)] transition-colors duration-500 disabled:opacity-40 disabled:cursor-not-allowed sm:min-w-[320px]"
                >
                  <span className="font-mono text-[11px] uppercase tracking-[0.22em] pl-1">
                    {submitting ? 'Отправляем…' : 'Отправить на модерацию'}
                  </span>
                  {submitting ? (
                    <ArrowPathIcon className="w-5 h-5 mr-1 animate-spin" />
                  ) : (
                    <ArrowRightIcon className="w-5 h-5 mr-1 transition-transform duration-500 group-hover:translate-x-1" />
                  )}
                </button>
              </div>
            </form>
          </motion.div>

          {/* Right — info */}
          <motion.aside
            className="lg:col-span-4"
            initial={prefersReduced ? false : { opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.15, ease: EASE_OUT }}
          >
            <div className="lg:sticky lg:top-24">
              <div className="flex items-baseline justify-between pb-3 border-b border-[var(--line)] mb-8">
                <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                  Как это работает
                </p>
                <InformationCircleIcon className="w-3.5 h-3.5 text-[var(--text-muted)]" />
              </div>

              <ol className="space-y-6">
                <SidebarStep
                  n="01"
                  icon={<SparklesIcon className="w-3.5 h-3.5 text-[var(--accent-yellow)]" />}
                  title="Отправка"
                  text="Вы заполняете форму — мы получаем заявку"
                />
                <SidebarStep
                  n="02"
                  icon={<ShieldCheckIcon className="w-3.5 h-3.5 text-[var(--accent-green)]" />}
                  title="Проверка"
                  text="Модератор проверяет данные и уточняет при необходимости"
                />
                <SidebarStep
                  n="03"
                  icon={<CheckCircleIcon className="w-3.5 h-3.5 text-[var(--accent-green)]" />}
                  title="Появление в каталоге"
                  text="Фильм становится доступен всем пользователям"
                />
              </ol>

              <div className="mt-10 pt-6 border-t border-[var(--line)] flex items-start gap-3">
                <ClockIcon className="w-3.5 h-3.5 shrink-0 mt-1 text-[var(--text-muted)]" />
                <p className="font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)] leading-relaxed">
                  Проверка обычно занимает 1–2 дня
                </p>
              </div>
            </div>
          </motion.aside>
        </div>
      </section>
    </div>
  );
}

/* ---------- Editorial field ---------- */

function EditorialField({
  label,
  htmlFor,
  hint,
  error,
  required,
  children,
}: {
  label: string;
  htmlFor: string;
  hint?: string;
  error?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div>
      <div className="flex items-baseline justify-between gap-2 mb-1">
        <label
          htmlFor={htmlFor}
          className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]"
        >
          {label}
          {required && <span className="ml-0.5 text-[var(--accent-red)]">*</span>}
        </label>
        {hint && !error && (
          <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)]">
            {hint}
          </span>
        )}
      </div>
      {children}
      {error && (
        <p className="mt-2 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--accent-red)]">
          {error}
        </p>
      )}
    </div>
  );
}

/* ---------- Sidebar step ---------- */

function SidebarStep({
  n,
  icon,
  title,
  text,
}: {
  n: string;
  icon: React.ReactNode;
  title: string;
  text: string;
}) {
  return (
    <li className="flex items-start gap-4">
      <span className="font-mono text-[10px] tracking-[0.2em] text-[var(--text-muted)] mt-1 shrink-0">
        {n}
      </span>
      <div className="min-w-0">
        <p className="flex items-center gap-2 font-serif text-lg leading-tight">
          {icon}
          {title}
        </p>
        <p className="mt-1 text-sm text-[var(--text-muted)] leading-snug">{text}</p>
      </div>
    </li>
  );
}

/* ---------- Success ---------- */

function SuccessState({
  titleRu,
  onAnother,
}: {
  titleRu: string;
  onAnother: () => void;
}) {
  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      <div className="max-w-[1400px] mx-auto px-6 lg:px-10 py-24 lg:py-32 text-center">
        <div className="inline-flex items-center gap-3 mb-8">
          <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-green)]" />
          <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-secondary)]">
            Успешно
          </p>
        </div>

        <h1 className="font-serif text-[clamp(2.75rem,10vw,7rem)] leading-[0.86] tracking-[-0.04em] mb-6">
          Заявка
          <br />
          <span className="italic">отправлена</span>
          <span className="text-[var(--accent-yellow)]">.</span>
        </h1>

        <p className="text-[var(--text-secondary)] max-w-lg mx-auto leading-relaxed mb-12">
          {titleRu ? <>«{titleRu}» отправлен на рассмотрение. </> : null}
          Мы сообщим, когда модератор проверит заявку — обычно это занимает 1–2 дня.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-6">
          <button onClick={onAnother} className="group inline-flex items-center gap-3">
            <span className="w-11 h-11 rounded-full bg-[var(--text-primary)] text-[var(--bg-primary)] grid place-items-center transition-transform duration-500 group-hover:rotate-[-8deg] group-hover:scale-105">
              <PlusCircleIcon className="w-5 h-5" />
            </span>
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-primary)] pb-1 border-b border-transparent group-hover:border-[var(--text-primary)] transition-colors">
              Предложить ещё
            </span>
          </button>

          <Link href="/" className="group inline-flex items-center gap-3">
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
              В каталог
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