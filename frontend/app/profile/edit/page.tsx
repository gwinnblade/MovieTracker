'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { motion, useReducedMotion } from 'framer-motion';
import { profileApi } from '@/lib/api/profile';
import { useAuthStore } from '@/store/useAuthStore';
import toast from 'react-hot-toast';
import {
  ChevronLeftIcon,
  EyeIcon,
  EyeSlashIcon,
  ArrowRightIcon,
  ArrowPathIcon,
  CheckIcon,
  XMarkIcon,
  ExclamationCircleIcon,
  InformationCircleIcon,
} from '@heroicons/react/24/outline';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const EASE_EDITORIAL = [0.76, 0, 0.24, 1] as const;
const PWD_MIN = 8;

const editSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(2, 'Минимум 2 символа')
      .max(100, 'Не длиннее 100 символов'),
    login: z
      .string()
      .trim()
      .min(3, 'Минимум 3 символа')
      .max(32, 'Не длиннее 32 символов')
      .regex(/^[a-zA-Z0-9_-]+$/, 'Только латиница, цифры, «_» и «-»'),
    email: z.string().trim().email('Некорректный email'),
    current_password: z.string().optional(),
    password: z.string().optional(),
    password_confirmation: z.string().optional(),
  })
  .superRefine((data, ctx) => {
    const wantsChange = (data.password ?? '').length > 0;
    if (!wantsChange) return;

    if (!data.current_password) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['current_password'],
        message: 'Введите текущий пароль',
      });
    }
    if ((data.password ?? '').length < PWD_MIN) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['password'],
        message: `Минимум ${PWD_MIN} символов`,
      });
    } else {
      if (!/[a-zA-Zа-яА-Я]/.test(data.password!)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['password'],
          message: 'Нужна хотя бы одна буква',
        });
      }
      if (!/\d/.test(data.password!)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['password'],
          message: 'Нужна хотя бы одна цифра',
        });
      }
    }
    if ((data.password_confirmation ?? '') !== data.password) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['password_confirmation'],
        message: 'Пароли не совпадают',
      });
    }
  });

type EditFormData = z.infer<typeof editSchema>;

export default function ProfileEditPage() {
  const router = useRouter();
  const prefersReduced = useReducedMotion();
  const fetchUser = useAuthStore((s) => s.fetchUser);

  const [loading, setLoading] = useState(true);
  const [formError, setFormError] = useState<string | null>(null);
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  const {
    register,
    handleSubmit,
    reset,
    watch,
    setError,
    formState: { errors, isSubmitting, isDirty },
  } = useForm<EditFormData>({
    resolver: zodResolver(editSchema),
    mode: 'onTouched',
  });

  const initialEmail = useRef<string>('');
  const initialLogin = useRef<string>('');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await profileApi.getProfile();
        if (cancelled) return;
        const initial = {
          name: data.user.name ?? '',
          login: data.user.login ?? '',
          email: data.user.email ?? '',
          current_password: '',
          password: '',
          password_confirmation: '',
        };
        reset(initial);
        initialEmail.current = initial.email;
        initialLogin.current = initial.login;
      } catch {
        toast.error('Не удалось загрузить данные профиля');
        router.replace('/profile');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [reset, router]);

  useEffect(() => {
    if (!isDirty) return;
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, [isDirty]);

  const pwd = watch('password') ?? '';
  const confirm = watch('password_confirmation') ?? '';
  const wantsPasswordChange = pwd.length > 0;
  const passwordMatch = confirm.length > 0 && pwd === confirm;
  const pwdChecks = [
    { ok: pwd.length >= PWD_MIN, label: `Минимум ${PWD_MIN} символов` },
    { ok: /[a-zA-Zа-яА-Я]/.test(pwd), label: 'Хотя бы одна буква' },
    { ok: /\d/.test(pwd), label: 'Хотя бы одна цифра' },
  ];
  const strength = pwdChecks.filter((c) => c.ok).length;

  const onSubmit = async (data: EditFormData) => {
    setFormError(null);
    try {
      const payload: Record<string, unknown> = {
        name: data.name.trim(),
        login: data.login.trim(),
        email: data.email.trim(),
      };
      if (wantsPasswordChange) {
        payload.current_password = data.current_password;
        payload.password = data.password;
        payload.password_confirmation = data.password_confirmation;
      }

      await profileApi.updateProfile(payload);
      await fetchUser().catch(() => {});
      toast.success('Профиль обновлён');

      setTimeout(() => router.replace('/profile'), 400);
    } catch (error: any) {
      const status = error?.response?.status;
      const apiErrors = error?.response?.data?.errors as
        | Record<string, string[]>
        | undefined;

      if (apiErrors && typeof apiErrors === 'object') {
        let handled = false;
        (Object.keys(apiErrors) as (keyof EditFormData)[]).forEach((field) => {
          if (field in data) {
            setError(field, { message: apiErrors[field]![0] });
            handled = true;
          }
        });
        if (handled) {
          setFormError('Проверьте подсвеченные поля');
          return;
        }
      }

      const msg =
        error?.response?.data?.message ??
        (status === 422
          ? 'Некорректные данные. Проверьте форму'
          : status === 401
            ? 'Требуется повторный вход'
            : error?.response
              ? 'Не удалось сохранить. Попробуйте ещё раз'
              : 'Нет соединения с сервером');
      setFormError(msg);
    }
  };

  if (loading) return <ProfileEditSkeleton />;

  const emailChanged = initialEmail.current && watch('email') !== initialEmail.current;
  const loginChanged = initialLogin.current && watch('login') !== initialLogin.current;

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      {/* ============ MASTHEAD ============ */}
      <section className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] font-mono text-[10px] sm:text-[11px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
            <Link
              href="/profile"
              className="group inline-flex items-center gap-2 hover:text-[var(--text-primary)] transition-colors"
            >
              <ChevronLeftIcon className="w-3.5 h-3.5 transition-transform group-hover:-translate-x-0.5" />
              <span>Назад к профилю</span>
            </Link>
            <span className="hidden sm:inline">Настройки аккаунта</span>
          </div>
        </div>

        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-12 lg:pb-16">
          <motion.div
            initial={prefersReduced ? false : { opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, ease: EASE_OUT }}
          >
            <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
              Редактирование
            </p>
            <h1 className="font-serif text-[clamp(2.75rem,10vw,8rem)] leading-[0.85] tracking-[-0.045em]">
              Профиль
              <span className="text-[var(--accent-yellow)]">.</span>
            </h1>
            <p className="mt-8 max-w-xl text-base sm:text-lg text-[var(--text-secondary)] leading-relaxed">
              Обновите личные данные и настройки безопасности
            </p>
          </motion.div>
        </div>
      </section>

      {/* ============ FORM ============ */}
      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
        <div className="grid lg:grid-cols-12 gap-12 lg:gap-16">
          {/* Левая колонка — подсказки */}
          <aside className="lg:col-span-3">
            <div className="lg:sticky lg:top-24 space-y-10">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-3">
                  Основное
                </p>
                <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
                  Имя видно в профиле, логин — в ссылке и упоминаниях, email — для связи.
                </p>
              </div>
              <div className="border-t border-[var(--line)] pt-8">
                <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-3">
                  Безопасность
                </p>
                <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
                  Пароль меняется только если вы заполните раздел ниже. Иначе оставьте поля пустыми.
                </p>
              </div>
            </div>
          </aside>

          {/* Форма */}
          <div className="lg:col-span-9 min-w-0">
            <form
              onSubmit={handleSubmit(onSubmit)}
              className="space-y-14"
              noValidate
              autoComplete="on"
            >
              {formError && (
                <motion.div
                  role="alert"
                  initial={prefersReduced ? false : { opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.35, ease: EASE_EDITORIAL }}
                  className="flex items-start gap-3 pl-4 border-l-2 border-[var(--accent-red)]"
                >
                  <ExclamationCircleIcon
                    className="w-4 h-4 text-[var(--accent-red)] shrink-0 mt-0.5"
                    aria-hidden="true"
                  />
                  <p className="font-mono text-[11px] uppercase tracking-[0.1em] text-[var(--accent-red)] leading-relaxed">
                    {formError}
                  </p>
                </motion.div>
              )}

              {/* ============ Основные данные ============ */}
              <fieldset>
                <legend className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-8 pb-3 border-b border-[var(--line)] w-full">
                  Основное
                </legend>

                <div className="grid gap-8">
                  <EditorialField
                    label="Имя"
                    htmlFor="name"
                    required
                    error={errors.name?.message}
                  >
                    <input
                      id="name"
                      type="text"
                      autoComplete="name"
                      placeholder="Иван Иванов"
                      disabled={isSubmitting}
                      aria-invalid={!!errors.name}
                      aria-describedby={errors.name ? 'name-error' : undefined}
                      className={editorialInputClass(!!errors.name)}
                      {...register('name')}
                    />
                  </EditorialField>

                  <EditorialField
                    label="Логин"
                    htmlFor="login"
                    required
                    error={errors.login?.message}
                    hint={
                      loginChanged
                        ? '@ сменится, старые ссылки перестанут работать'
                        : undefined
                    }
                  >
                    <div className="relative">
                      <span className="absolute left-0 top-1/2 -translate-y-1/2 font-mono text-xl text-[var(--text-muted)] pointer-events-none">
                        @
                      </span>
                      <input
                        id="login"
                        type="text"
                        autoComplete="username"
                        autoCapitalize="none"
                        spellCheck={false}
                        placeholder="ivan_123"
                        disabled={isSubmitting}
                        aria-invalid={!!errors.login}
                        aria-describedby={errors.login ? 'login-error' : undefined}
                        className={`${editorialInputClass(!!errors.login)} pl-7`}
                        {...register('login')}
                      />
                    </div>
                  </EditorialField>

                  <EditorialField
                    label="Email"
                    htmlFor="email"
                    required
                    error={errors.email?.message}
                    hint={
                      emailChanged ? 'Может потребоваться подтверждение' : undefined
                    }
                  >
                    <input
                      id="email"
                      type="email"
                      autoComplete="email"
                      autoCapitalize="none"
                      spellCheck={false}
                      placeholder="ivan@example.com"
                      disabled={isSubmitting}
                      aria-invalid={!!errors.email}
                      aria-describedby={errors.email ? 'email-error' : undefined}
                      className={editorialInputClass(!!errors.email)}
                      {...register('email')}
                    />
                  </EditorialField>
                </div>
              </fieldset>

              {/* ============ Смена пароля ============ */}
              <fieldset>
                <legend className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-8 pb-3 border-b border-[var(--line)] w-full">
                  Смена пароля{' '}
                  <span className="normal-case tracking-normal text-[var(--text-muted)]/70">
                    · опционально
                  </span>
                </legend>

                <p className="text-sm text-[var(--text-secondary)] mb-8 max-w-xl leading-relaxed">
                  Заполните поля ниже, только если хотите сменить пароль.
                </p>

                <div className="grid gap-8">
                  <EditorialField
                    label="Текущий пароль"
                    htmlFor="current_password"
                    required={wantsPasswordChange}
                    error={errors.current_password?.message}
                  >
                    <div className="relative">
                      <input
                        id="current_password"
                        type={showCurrent ? 'text' : 'password'}
                        autoComplete="current-password"
                        placeholder="••••••••"
                        disabled={isSubmitting}
                        aria-invalid={!!errors.current_password}
                        aria-describedby={
                          errors.current_password ? 'current_password-error' : undefined
                        }
                        className={`${editorialInputClass(!!errors.current_password)} pr-12`}
                        {...register('current_password')}
                      />
                      <PasswordToggle
                        shown={showCurrent}
                        onToggle={() => setShowCurrent((v) => !v)}
                        disabled={isSubmitting}
                      />
                    </div>
                  </EditorialField>

                  <div className="grid sm:grid-cols-2 gap-8">
                    <EditorialField
                      label="Новый пароль"
                      htmlFor="password"
                      error={errors.password?.message}
                    >
                      <div className="relative">
                        <input
                          id="password"
                          type={showNew ? 'text' : 'password'}
                          autoComplete="new-password"
                          placeholder="••••••••"
                          disabled={isSubmitting}
                          aria-invalid={!!errors.password}
                          aria-describedby={
                            errors.password ? 'password-error' : undefined
                          }
                          className={`${editorialInputClass(!!errors.password)} pr-12`}
                          {...register('password')}
                        />
                        <PasswordToggle
                          shown={showNew}
                          onToggle={() => setShowNew((v) => !v)}
                          disabled={isSubmitting}
                        />
                      </div>
                    </EditorialField>

                    <EditorialField
                      label="Подтверждение"
                      htmlFor="password_confirmation"
                      error={errors.password_confirmation?.message}
                    >
                      <div className="relative">
                        <input
                          id="password_confirmation"
                          type={showConfirm ? 'text' : 'password'}
                          autoComplete="new-password"
                          placeholder="••••••••"
                          disabled={isSubmitting}
                          aria-invalid={!!errors.password_confirmation}
                          aria-describedby={
                            errors.password_confirmation
                              ? 'password_confirmation-error'
                              : undefined
                          }
                          className={`${editorialInputClass(
                            !!errors.password_confirmation
                          )} pr-12`}
                          {...register('password_confirmation')}
                        />
                        <PasswordToggle
                          shown={showConfirm}
                          onToggle={() => setShowConfirm((v) => !v)}
                          disabled={isSubmitting}
                        />
                      </div>
                    </EditorialField>
                  </div>

                  {wantsPasswordChange && (
                    <div className="pt-4">
                      <div className="flex gap-1.5 mb-4">
                        {[0, 1, 2].map((i) => (
                          <div
                            key={i}
                            className={`h-[2px] flex-1 transition-colors duration-500 ${
                              i < strength
                                ? strength === 1
                                  ? 'bg-[var(--accent-red)]'
                                  : strength === 2
                                    ? 'bg-[var(--accent-yellow)]'
                                    : 'bg-[var(--accent-green)]'
                                : 'bg-[var(--line)]'
                            }`}
                          />
                        ))}
                      </div>
                      <ul className="space-y-1.5">
                        {pwdChecks.map((c, i) => (
                          <li
                            key={i}
                            className={`font-mono text-[10px] uppercase tracking-[0.15em] flex items-center gap-2 ${
                              c.ok
                                ? 'text-[var(--accent-green)]'
                                : 'text-[var(--text-muted)]'
                            }`}
                          >
                            {c.ok ? (
                              <CheckIcon className="w-3 h-3 shrink-0" aria-hidden="true" />
                            ) : (
                              <XMarkIcon
                                className="w-3 h-3 shrink-0 opacity-60"
                                aria-hidden="true"
                              />
                            )}
                            {c.label}
                          </li>
                        ))}
                      </ul>
                      {confirm.length > 0 && (
                        <p
                          className={`mt-3 font-mono text-[10px] uppercase tracking-[0.15em] flex items-center gap-2 ${
                            passwordMatch
                              ? 'text-[var(--accent-green)]'
                              : 'text-[var(--accent-red)]'
                          }`}
                        >
                          {passwordMatch ? (
                            <>
                              <CheckIcon className="w-3 h-3" aria-hidden="true" />{' '}
                              Пароли совпадают
                            </>
                          ) : (
                            <>
                              <XMarkIcon className="w-3 h-3" aria-hidden="true" />{' '}
                              Пароли не совпадают
                            </>
                          )}
                        </p>
                      )}
                    </div>
                  )}
                </div>
              </fieldset>

              {/* ============ Действия ============ */}
              <div className="flex flex-col-reverse sm:flex-row sm:items-center sm:justify-between gap-4 pt-8 border-t border-[var(--line)]">
                <Link
                  href="/profile"
                  className="font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--text-muted)] hover:text-[var(--text-primary)] border-b border-transparent hover:border-[var(--text-primary)] pb-0.5 transition-colors self-start sm:self-auto"
                >
                  Отмена
                </Link>

                <button
                  type="submit"
                  disabled={isSubmitting || !isDirty}
                  className="group inline-flex items-center justify-between gap-6 sm:gap-10 px-0 sm:px-2 py-4 border-y-2 border-[var(--text-primary)] text-[var(--text-primary)] hover:bg-[var(--text-primary)] hover:text-[var(--bg-primary)] transition-colors duration-500 disabled:opacity-40 disabled:cursor-not-allowed sm:min-w-[280px]"
                >
                  <span className="font-mono text-[11px] uppercase tracking-[0.22em] pl-1">
                    {isSubmitting ? 'Сохранение…' : 'Сохранить изменения'}
                  </span>
                  {isSubmitting ? (
                    <ArrowPathIcon className="w-5 h-5 mr-1 animate-spin" aria-hidden="true" />
                  ) : (
                    <ArrowRightIcon
                      className="w-5 h-5 mr-1 transition-transform duration-500 group-hover:translate-x-1"
                      aria-hidden="true"
                    />
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      </section>
    </div>
  );
}

/* ---------- Поле в редакционном стиле ---------- */

function editorialInputClass(error: boolean) {
  return `w-full bg-transparent border-0 border-b ${
    error ? 'border-[var(--accent-red)]' : 'border-[var(--line)]'
  } rounded-none px-0 py-3 text-lg sm:text-xl font-serif tracking-[-0.005em] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] placeholder:italic placeholder:opacity-60 focus:outline-none ${
    error ? 'focus:border-[var(--accent-red)]' : 'focus:border-[var(--accent-yellow)]'
  } transition-colors disabled:opacity-50`;
}

function EditorialField({
  label,
  htmlFor,
  error,
  hint,
  required,
  children,
}: {
  label: string;
  htmlFor: string;
  error?: string;
  hint?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label
        htmlFor={htmlFor}
        className="block font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] mb-1"
      >
        {label}
        {required && (
          <span className="ml-0.5 text-[var(--accent-red)]" aria-hidden="true">
            *
          </span>
        )}
      </label>
      {children}
      {hint && !error && (
        <p className="mt-2 font-mono text-[10px] uppercase tracking-[0.12em] text-[var(--text-muted)] flex items-center gap-1.5">
          <InformationCircleIcon className="w-3 h-3 shrink-0" aria-hidden="true" />
          {hint}
        </p>
      )}
      {error && (
        <p
          id={`${htmlFor}-error`}
          className="mt-2 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--accent-red)]"
        >
          {error}
        </p>
      )}
    </div>
  );
}

/* ---------- Кнопка «показать пароль» ---------- */

function PasswordToggle({
  shown,
  onToggle,
  disabled,
}: {
  shown: boolean;
  onToggle: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      disabled={disabled}
      aria-label={shown ? 'Скрыть пароль' : 'Показать пароль'}
      tabIndex={-1}
      className="absolute right-0 top-1/2 -translate-y-1/2 p-2 text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors disabled:opacity-50"
    >
      {shown ? (
        <EyeSlashIcon className="w-4 h-4" aria-hidden="true" />
      ) : (
        <EyeIcon className="w-4 h-4" aria-hidden="true" />
      )}
    </button>
  );
}

/* ---------- Skeleton ---------- */

function ProfileEditSkeleton() {
  return (
    <div className="min-h-screen bg-[var(--bg-primary)]">
      <section className="border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-8 lg:pt-10">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] animate-pulse">
            <div className="h-2.5 w-32 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-2.5 w-28 bg-[var(--bg-tertiary)] rounded" />
          </div>
        </div>
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10 pt-16 lg:pt-24 pb-12 lg:pb-16 animate-pulse">
          <div className="h-3 w-28 bg-[var(--bg-tertiary)] rounded mb-6" />
          <div className="h-24 w-2/3 bg-[var(--bg-tertiary)] rounded" />
          <div className="h-4 w-1/2 bg-[var(--bg-tertiary)] rounded mt-8" />
        </div>
      </section>
      <section className="max-w-[1400px] mx-auto px-6 lg:px-10 py-16 lg:py-24">
        <div className="grid lg:grid-cols-12 gap-12 lg:gap-16 animate-pulse">
          <div className="lg:col-span-3 space-y-4">
            <div className="h-2.5 w-24 bg-[var(--bg-tertiary)] rounded" />
            <div className="h-3 w-full bg-[var(--bg-tertiary)] rounded" />
          </div>
          <div className="lg:col-span-9 space-y-8">
            <div className="h-2.5 w-28 bg-[var(--bg-tertiary)] rounded mb-8" />
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="space-y-2">
                <div className="h-2.5 w-20 bg-[var(--bg-tertiary)] rounded" />
                <div className="h-10 w-full bg-[var(--bg-tertiary)] rounded" />
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}