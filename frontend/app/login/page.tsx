'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
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
  ArrowRightIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline';

const loginSchema = z.object({
  login: z.string().min(1, 'Введите логин или email'),
  password: z.string().min(1, 'Введите пароль'),
});

type LoginFormData = z.infer<typeof loginSchema>;

const EASE_OUT = [0.16, 1, 0.3, 1] as const;
const EASE_EDITORIAL = [0.76, 0, 0.24, 1] as const;

const BENEFITS = [
  {
    num: '01',
    title: 'Дневник',
    text: 'Дневник просмотров с оценками и заметками',
  },
  {
    num: '02',
    title: 'Подбор',
    text: 'Умный подбор «что посмотреть» на вечер',
  },
  {
    num: '03',
    title: 'Списки',
    text: 'Тематические подборки и списки',
  },
];

export default function LoginPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const prefersReduced = useReducedMotion();
  const { login, isLoading } = useAuthStore();
  const [showPassword, setShowPassword] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const redirectTo = searchParams.get('redirect') || '/';

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: { login: '', password: '' },
  });

  const onSubmit = async (data: LoginFormData) => {
    setFormError(null);
    try {
      await login(data);
      toast.success('Добро пожаловать!');
      router.replace(redirectTo);
      router.refresh();
    } catch (error: any) {
      const status = error?.response?.status;
      const msg =
        error?.response?.data?.message ??
        (status === 401
          ? 'Неверный логин или пароль'
          : status === 429
            ? 'Слишком много попыток. Попробуйте через минуту'
            : error?.response
              ? 'Не удалось войти. Попробуйте ещё раз'
              : 'Нет соединения с сервером');
      setFormError(msg);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)] grid lg:grid-cols-12">
      {/* ============ LEFT — editorial brand panel ============ */}
      <aside className="relative hidden lg:flex lg:col-span-5 flex-col justify-between bg-[var(--accent-yellow)] overflow-hidden p-10 xl:p-14">
        {/* Film grain */}
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

        {/* Top brand row */}
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

        {/* Center manifesto */}
        <div className="relative max-w-[440px]">
          <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-black/60 mb-6">
            Вход в аккаунт
          </p>
          <h2 className="font-serif text-[clamp(2.5rem,5.5vw,4.5rem)] leading-[0.92] tracking-[-0.03em] text-black">
            Все фильмы,
            <br />
            которые вы
            <br />
            <span className="italic">посмотрели</span> —
            <br />
            в одном месте
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
                  <p className="font-serif text-lg text-black leading-tight">
                    {b.title}
                  </p>
                  <p className="mt-1 text-sm text-black/70 leading-snug">
                    {b.text}
                  </p>
                </div>
              </motion.li>
            ))}
          </ul>
        </div>

        {/* Bottom copyright */}
        <div className="relative flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.25em] text-black/60">
          <span>© {new Date().getFullYear()} MovieTracker</span>
          <span className="hidden xl:inline">Кинодневник</span>
        </div>
      </aside>

      {/* ============ RIGHT — form ============ */}
      <main className="lg:col-span-7 flex flex-col">
        {/* Top bar */}
        <div className="px-6 sm:px-10 lg:px-14 xl:px-20 pt-8">
          <div className="flex items-center justify-between pb-5 border-b border-[var(--line)] font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
            <Link
              href="/"
              className="lg:hidden inline-flex items-center gap-2 hover:text-[var(--text-primary)] transition-colors"
            >
              <FilmIcon className="w-3.5 h-3.5" />
              MovieTracker
            </Link>
            <span className="hidden lg:inline">MovieTracker — Вход</span>
            <Link
              href="/register"
              className="group inline-flex items-center gap-2 hover:text-[var(--text-primary)] transition-colors"
            >
              Регистрация
              <ArrowRightIcon className="w-3.5 h-3.5 transition-transform duration-500 group-hover:translate-x-0.5" />
            </Link>
          </div>
        </div>

        {/* Form body */}
        <div className="flex-1 flex items-center px-6 sm:px-10 lg:px-14 xl:px-20 py-14 lg:py-20">
          <motion.div
            className="w-full max-w-[520px]"
            initial={prefersReduced ? false : { opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 1, ease: EASE_OUT }}
          >
            {/* Editorial heading */}
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
                Добро пожаловать
              </p>
              <h1 className="font-serif text-[clamp(2.75rem,6vw,5.5rem)] leading-[0.88] tracking-[-0.04em]">
                С возвращением
                <span className="text-[var(--accent-yellow)]">.</span>
              </h1>
              <p className="mt-6 max-w-md text-base text-[var(--text-secondary)] leading-relaxed">
                Войдите, чтобы продолжить вести дневник
              </p>
            </div>

            {/* Error strip */}
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

            {/* Form */}
            <form
              onSubmit={handleSubmit(onSubmit)}
              className="mt-10 space-y-8"
              noValidate
              autoComplete="on"
            >
              {/* Логин */}
              <div className="group">
                <label
                  htmlFor="login"
                  className="block font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] mb-2"
                >
                  Логин или Email
                </label>
                <input
                  id="login"
                  type="text"
                  placeholder="username или you@example.com"
                  autoComplete="username"
                  autoFocus
                  spellCheck={false}
                  autoCapitalize="none"
                  disabled={isLoading}
                  className="w-full bg-transparent border-0 border-b border-[var(--line)] rounded-none px-0 py-3 text-xl sm:text-2xl font-serif tracking-[-0.01em] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] placeholder:italic placeholder:opacity-60 focus:outline-none focus:border-[var(--accent-yellow)] transition-colors disabled:opacity-50"
                  {...register('login')}
                  aria-invalid={errors.login ? 'true' : 'false'}
                />
                {errors.login?.message && (
                  <p className="mt-2 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--accent-red)]">
                    {errors.login.message}
                  </p>
                )}
              </div>

              {/* Пароль */}
              <div className="group relative">
                <label
                  htmlFor="password"
                  className="block font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] mb-2"
                >
                  Пароль
                </label>
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="••••••••"
                  autoComplete="current-password"
                  disabled={isLoading}
                  className="w-full bg-transparent border-0 border-b border-[var(--line)] rounded-none pl-0 pr-12 py-3 text-xl sm:text-2xl font-serif tracking-[-0.01em] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] placeholder:italic placeholder:opacity-60 focus:outline-none focus:border-[var(--accent-yellow)] transition-colors disabled:opacity-50"
                  {...register('password')}
                  aria-invalid={errors.password ? 'true' : 'false'}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? 'Скрыть пароль' : 'Показать пароль'}
                  tabIndex={-1}
                  className="absolute right-0 top-[2.6rem] p-2 text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                >
                  {showPassword ? (
                    <EyeSlashIcon className="w-4 h-4" />
                  ) : (
                    <EyeIcon className="w-4 h-4" />
                  )}
                </button>
                {errors.password?.message && (
                  <p className="mt-2 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--accent-red)]">
                    {errors.password.message}
                  </p>
                )}
              </div>

              {/* Забыли пароль */}
              <div className="flex items-center justify-end pt-1">
                <Link
                  href="/forgot-password"
                  className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] hover:text-[var(--text-primary)] border-b border-transparent hover:border-[var(--text-primary)] pb-0.5 transition-colors"
                >
                  Забыли пароль?
                </Link>
              </div>

              {/* Submit */}
              <button
                type="submit"
                disabled={isLoading}
                className="group w-full flex items-center justify-between py-5 border-y-2 border-[var(--text-primary)] text-[var(--text-primary)] hover:bg-[var(--text-primary)] hover:text-[var(--bg-primary)] transition-colors duration-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <span className="font-mono text-[11px] uppercase tracking-[0.25em] pl-1">
                  {isLoading ? 'Входим…' : 'Войти'}
                </span>
                {isLoading ? (
                  <ArrowPathIcon className="w-5 h-5 mr-1 animate-spin" />
                ) : (
                  <ArrowRightIcon className="w-5 h-5 mr-1 transition-transform duration-500 group-hover:translate-x-1" />
                )}
              </button>
            </form>

            {/* Footer */}
            <div className="mt-12 pt-8 border-t border-[var(--line)] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]">
                Нет аккаунта?
              </p>
              <Link
                href="/register"
                className="group inline-flex items-center gap-3"
              >
                <span className="font-serif text-lg italic text-[var(--text-primary)] group-hover:text-[var(--accent-yellow)] transition-colors">
                  Зарегистрироваться
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