'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { motion, useReducedMotion } from 'framer-motion';
import { useAuthStore } from '@/store/useAuthStore';
import toast from 'react-hot-toast';
import {
  EyeIcon,
  EyeSlashIcon,
  ExclamationCircleIcon,
  FilmIcon,
  CheckIcon,
  XMarkIcon,
  ArrowRightIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline';

const PASSWORD_MIN = 8;

const registerSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(2, 'Имя должно быть не менее 2 символов')
      .max(100, 'Слишком длинное имя'),
    login: z
      .string()
      .trim()
      .min(3, 'Логин должен быть не менее 3 символов')
      .max(32, 'Не длиннее 32 символов')
      .regex(/^[a-zA-Z0-9_-]+$/, 'Только латиница, цифры, «_» и «-»'),
    email: z.string().trim().email('Некорректный email'),
    password: z
      .string()
      .min(PASSWORD_MIN, `Минимум ${PASSWORD_MIN} символов`)
      .regex(/[a-zA-Zа-яА-Я]/, 'Нужна хотя бы одна буква')
      .regex(/\d/, 'Нужна хотя бы одна цифра'),
    password_confirmation: z.string(),
    agree: z.boolean().refine((v) => v === true, {
      message: 'Примите условия, чтобы продолжить',
    }),
  })
  .refine((d) => d.password === d.password_confirmation, {
    message: 'Пароли не совпадают',
    path: ['password_confirmation'],
  });

type RegisterFormData = z.infer<typeof registerSchema>;

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const EASE_EDITORIAL = [0.76, 0, 0.24, 1] as const;

const BENEFITS = [
  {
    num: '01',
    title: 'Дневник',
    text: 'Дневник с отметками, оценками и рецензиями',
  },
  {
    num: '02',
    title: 'Рулетка',
    text: 'Случайный фильм, когда не знаете, что посмотреть',
  },
  {
    num: '03',
    title: 'Подборки',
    text: 'Приватные и публичные подборки',
  },
];

export default function RegisterPage() {
  const router = useRouter();
  const prefersReduced = useReducedMotion();
  const { register: registerUser, isLoading } = useAuthStore();

  const [showPassword, setShowPassword] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors, isSubmitting },
  } = useForm<RegisterFormData>({
    resolver: zodResolver(registerSchema),
    mode: 'onTouched',
    defaultValues: {
      name: '',
      login: '',
      email: '',
      password: '',
      password_confirmation: '',
      agree: false,
    },
  });

  const password = watch('password') ?? '';
  const confirm = watch('password_confirmation') ?? '';
  const passwordMatch = confirm.length > 0 && password === confirm;

  const checks = useMemo(
    () => [
      { ok: password.length >= PASSWORD_MIN, label: `Минимум ${PASSWORD_MIN} символов` },
      { ok: /[a-zA-Zа-яА-Я]/.test(password), label: 'Хотя бы одна буква' },
      { ok: /\d/.test(password), label: 'Хотя бы одна цифра' },
    ],
    [password]
  );
  const strength = checks.filter((c) => c.ok).length;
  const busy = isLoading || isSubmitting;

  const onSubmit = async (data: RegisterFormData) => {
    setFormError(null);
    try {
      await registerUser({
        name: data.name,
        login: data.login,
        email: data.email,
        password: data.password,
        password_confirmation: data.password_confirmation,
      });
      toast.success('Аккаунт создан. Добро пожаловать!');
      router.replace('/');
      router.refresh();
    } catch (error: any) {
      const status = error?.response?.status;
      const apiMessage = error?.response?.data?.message;
      const msg =
        apiMessage ??
        (status === 409
          ? 'Логин или email уже заняты'
          : status === 422
            ? 'Проверьте заполнение формы'
            : status === 429
              ? 'Слишком много попыток. Попробуйте позже'
              : error?.response
                ? 'Не удалось создать аккаунт. Попробуйте ещё раз'
                : 'Нет соединения с сервером');
      setFormError(msg);
    }
  };

  return (
    <div className="min-h-screen grid lg:grid-cols-12 bg-[var(--bg-primary)] text-[var(--text-primary)]">
      {/* ============ LEFT — editorial manifesto ============ */}
      <aside className="relative hidden lg:flex lg:col-span-5 flex-col justify-between bg-[var(--accent-yellow)] overflow-hidden p-10 xl:p-14">
        <div
          aria-hidden
          className="absolute inset-0 opacity-[0.06]"
          style={{
            backgroundImage:
              'repeating-linear-gradient(90deg, #000 0, #000 1px, transparent 1px, transparent 10px)',
          }}
        />
        <div
          aria-hidden
          className="absolute -bottom-32 -right-32 w-[420px] h-[420px] rounded-full bg-black/[0.04] blur-3xl"
        />

        <div className="relative flex items-center justify-between">
          <Link
            href="/"
            className="inline-flex items-center gap-2 text-black font-mono text-[11px] uppercase tracking-[0.25em]"
          >
            <FilmIcon className="w-4 h-4" />
            MovieTracker
          </Link>
          <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-black/60">
            Est. 2024
          </span>
        </div>

        <div className="relative max-w-[440px]">
          <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-black/60 mb-6">
            Начните сегодня
          </p>
          <h2 className="font-serif text-[clamp(2.5rem,5.5vw,4.5rem)] leading-[0.92] tracking-[-0.03em] text-black">
            Начните вести
            <br />
            <span className="italic">кинодневник</span>
            <br />
            за минуту
          </h2>

          <ul className="mt-12 border-t border-black/20">
            {BENEFITS.map((b, i) => (
              <motion.li
                key={b.num}
                initial={prefersReduced ? false : { opacity: 0, x: -12 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{
                  duration: 0.7,
                  delay: 0.2 + i * 0.08,
                  ease: EASE_OUT,
                }}
                className="flex items-start gap-5 py-4 border-b border-black/20"
              >
                <span className="font-mono text-[10px] tracking-[0.2em] text-black/50 mt-1 shrink-0">
                  {b.num}
                </span>
                <div className="min-w-0">
                  <p className="font-serif text-lg text-black leading-tight">{b.title}</p>
                  <p className="mt-1 text-sm text-black/70 leading-snug">{b.text}</p>
                </div>
              </motion.li>
            ))}
          </ul>
        </div>

        <div className="relative flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.25em] text-black/60">
          <span>© {new Date().getFullYear()} MovieTracker</span>
          <span className="hidden xl:inline">Кинодневник</span>
        </div>
      </aside>

      {/* ============ RIGHT — form ============ */}
      <main className="lg:col-span-7 flex flex-col">
        <div className="px-6 sm:px-10 lg:px-14 xl:px-20 pt-8">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
            <Link
              href="/"
              className="lg:hidden inline-flex items-center gap-2 hover:text-[var(--text-primary)] transition-colors"
            >
              <FilmIcon className="w-3.5 h-3.5" />
              MovieTracker
            </Link>
            <span className="hidden lg:inline">MovieTracker — Регистрация</span>
            <Link
              href="/login"
              className="group inline-flex items-center gap-2 hover:text-[var(--text-primary)] transition-colors"
            >
              Вход
              <ArrowRightIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:translate-x-0.5" />
            </Link>
          </div>
        </div>

        <div className="flex-1 flex items-center px-6 sm:px-10 lg:px-14 xl:px-20 py-14 lg:py-20">
          <motion.div
            className="w-full max-w-[560px]"
            initial={prefersReduced ? false : { opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 1, ease: EASE_OUT }}
          >
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
                Новичок в клубе
              </p>
              <h1 className="font-serif text-[clamp(2.75rem,6vw,5.5rem)] leading-[0.88] tracking-[-0.04em]">
                Создать
                <br />
                <span className="italic">аккаунт</span>
                <span className="text-[var(--accent-yellow)]">.</span>
              </h1>
              <p className="mt-6 max-w-md text-base text-[var(--text-secondary)] leading-relaxed">
                Займёт меньше минуты
              </p>
            </div>

            {formError && (
              <motion.div
                role="alert"
                initial={prefersReduced ? false : { opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.35, ease: EASE_EDITORIAL }}
                className="mt-8 flex items-start gap-3 pl-4 border-l-2 border-[var(--accent-red)]"
              >
                <ExclamationCircleIcon className="w-4 h-4 text-[var(--accent-red)] shrink-0 mt-0.5" />
                <p className="font-mono text-[11px] uppercase tracking-[0.1em] text-[var(--accent-red)] leading-relaxed">
                  {formError}
                </p>
              </motion.div>
            )}

            <form
              onSubmit={handleSubmit(onSubmit)}
              className="mt-10 space-y-8"
              noValidate
              autoComplete="on"
            >
              {/* Имя */}
              <EditorialField
                label="Имя"
                htmlFor="name"
                required
                error={errors.name?.message}
              >
                <input
                  id="name"
                  type="text"
                  placeholder="Иван Иванов"
                  autoComplete="name"
                  autoFocus
                  disabled={busy}
                  aria-invalid={!!errors.name}
                  className={editorialInputClass(!!errors.name)}
                  {...register('name')}
                />
              </EditorialField>

              {/* Логин */}
              <EditorialField
                label="Логин"
                htmlFor="login"
                required
                error={errors.login?.message}
              >
                <div className="relative">
                  <span className="absolute left-0 top-1/2 -translate-y-1/2 font-mono text-xl text-[var(--text-muted)] pointer-events-none">
                    @
                  </span>
                  <input
                    id="login"
                    type="text"
                    placeholder="ivan_123"
                    autoComplete="username"
                    autoCapitalize="none"
                    spellCheck={false}
                    disabled={busy}
                    aria-invalid={!!errors.login}
                    className={`${editorialInputClass(!!errors.login)} pl-7`}
                    {...register('login')}
                  />
                </div>
              </EditorialField>

              {/* Email */}
              <EditorialField
                label="Email"
                htmlFor="email"
                required
                error={errors.email?.message}
              >
                <input
                  id="email"
                  type="email"
                  placeholder="ivan@example.com"
                  autoComplete="email"
                  autoCapitalize="none"
                  spellCheck={false}
                  disabled={busy}
                  aria-invalid={!!errors.email}
                  className={editorialInputClass(!!errors.email)}
                  {...register('email')}
                />
              </EditorialField>

              {/* Пароль */}
              <EditorialField
                label="Пароль"
                htmlFor="password"
                required
                error={errors.password?.message}
              >
                <div className="relative">
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="••••••••"
                    autoComplete="new-password"
                    disabled={busy}
                    aria-invalid={!!errors.password}
                    className={`${editorialInputClass(!!errors.password)} pr-12`}
                    {...register('password')}
                  />
                  <PasswordToggle
                    shown={showPassword}
                    onToggle={() => setShowPassword((v) => !v)}
                    disabled={busy}
                  />
                </div>

                <div className="mt-4 flex gap-1.5">
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

                <ul className="mt-3 space-y-1.5">
                  {checks.map((c, i) => (
                    <li
                      key={i}
                      className={`font-mono text-[10px] uppercase tracking-[0.15em] flex items-center gap-2 ${
                        c.ok ? 'text-[var(--accent-green)]' : 'text-[var(--text-muted)]'
                      }`}
                    >
                      {c.ok ? (
                        <CheckIcon className="w-3 h-3 shrink-0" />
                      ) : (
                        <XMarkIcon className="w-3 h-3 shrink-0 opacity-60" />
                      )}
                      {c.label}
                    </li>
                  ))}
                </ul>
              </EditorialField>

              {/* Подтверждение */}
              <EditorialField
                label="Подтверждение пароля"
                htmlFor="password_confirmation"
                error={errors.password_confirmation?.message}
              >
                <input
                  id="password_confirmation"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="••••••••"
                  autoComplete="new-password"
                  disabled={busy}
                  aria-invalid={!!errors.password_confirmation}
                  className={editorialInputClass(!!errors.password_confirmation)}
                  {...register('password_confirmation')}
                />
                {confirm.length > 0 && (
                  <p
                    className={`mt-2 font-mono text-[10px] uppercase tracking-[0.15em] flex items-center gap-2 ${
                      passwordMatch
                        ? 'text-[var(--accent-green)]'
                        : 'text-[var(--accent-red)]'
                    }`}
                  >
                    {passwordMatch ? (
                      <>
                        <CheckIcon className="w-3 h-3" /> Пароли совпадают
                      </>
                    ) : (
                      <>
                        <XMarkIcon className="w-3 h-3" /> Пароли не совпадают
                      </>
                    )}
                  </p>
                )}
              </EditorialField>

              {/* Согласие */}
              <div>
                <label className="flex items-start gap-3 cursor-pointer group">
                  <span
                    className={`mt-0.5 w-4 h-4 shrink-0 border transition-colors grid place-items-center ${
                      watch('agree')
                        ? 'bg-[var(--text-primary)] border-[var(--text-primary)]'
                        : 'border-[var(--line)] group-hover:border-[var(--text-primary)]'
                    }`}
                  >
                    {watch('agree') && (
                      <CheckIcon className="w-2.5 h-2.5 text-[var(--bg-primary)]" />
                    )}
                  </span>
                  <input
                    id="agree"
                    type="checkbox"
                    {...register('agree')}
                    disabled={busy}
                    aria-invalid={!!errors.agree}
                    className="sr-only"
                  />
                  <span className="text-sm text-[var(--text-secondary)] leading-snug select-none">
                    Я принимаю{' '}
                    <Link
                      href="/terms"
                      className="text-[var(--text-primary)] underline-offset-2 hover:underline hover:text-[var(--accent-yellow)] transition-colors"
                    >
                      условия сервиса
                    </Link>{' '}
                    и{' '}
                    <Link
                      href="/privacy"
                      className="text-[var(--text-primary)] underline-offset-2 hover:underline hover:text-[var(--accent-yellow)] transition-colors"
                    >
                      политику конфиденциальности
                    </Link>
                  </span>
                </label>
                {errors.agree && (
                  <p className="mt-2 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--accent-red)]">
                    {errors.agree.message}
                  </p>
                )}
              </div>

              {/* Submit */}
              <button
                type="submit"
                disabled={busy}
                className="group w-full flex items-center justify-between py-5 border-y-2 border-[var(--text-primary)] text-[var(--text-primary)] hover:bg-[var(--text-primary)] hover:text-[var(--bg-primary)] transition-colors duration-500 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <span className="font-mono text-[11px] uppercase tracking-[0.25em] pl-1">
                  {busy ? 'Создаём аккаунт…' : 'Создать аккаунт'}
                </span>
                {busy ? (
                  <ArrowPathIcon className="w-5 h-5 mr-1 animate-spin" />
                ) : (
                  <ArrowRightIcon className="w-5 h-5 mr-1 transition-transform duration-500 group-hover:translate-x-1" />
                )}
              </button>
            </form>

            {/* Footer */}
            <div className="mt-12 pt-8 border-t border-[var(--line)] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                Уже есть аккаунт?
              </p>
              <Link href="/login" className="group inline-flex items-center gap-3">
                <span className="font-serif text-lg italic text-[var(--text-primary)] group-hover:text-[var(--accent-yellow)] transition-colors">
                  Войти
                </span>
                <span className="w-9 h-9 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
                  <ArrowRightIcon className="w-4 h-4 transition-transform duration-500 group-hover:translate-x-0.5" />
                </span>
              </Link>
            </div>
          </motion.div>
        </div>
      </main>
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
  required,
  children,
}: {
  label: string;
  htmlFor: string;
  error?: string;
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
      {error && (
        <p className="mt-2 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--accent-red)]">
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
        <EyeSlashIcon className="w-4 h-4" />
      ) : (
        <EyeIcon className="w-4 h-4" />
      )}
    </button>
  );
}