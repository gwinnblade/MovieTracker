// frontend/components/ui/Header.tsx
'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useAuthStore } from '@/store/useAuthStore';
import GlobalSearch from '@/components/ui/GlobalSearch';
import { useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import {
  FilmIcon,
  ShieldCheckIcon,
  ArrowRightOnRectangleIcon,
  Bars3Icon,
  XMarkIcon,
  ArrowUpRightIcon,
} from '@heroicons/react/24/outline';

const NAV = [
  { href: '/catalog', label: 'Каталог' },
  { href: '/entries', label: 'Отметки' },
  { href: '/lists', label: 'Списки' },
  { href: '/random', label: 'Случайное' },
  { href: '/suggest', label: 'Предложить' },
] as const;

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

export default function Header() {
  const pathname = usePathname();
  const router = useRouter();
  const prefersReduced = useReducedMotion();
  const { user, isAuthenticated, fetchUser, logout, isLoading } = useAuthStore();

  const [mobileOpen, setMobileOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const userMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isAuthenticated) return;
    fetchUser().catch(() => {});
  }, []);

  useEffect(() => {
    setMobileOpen(false);
    setUserMenuOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!mobileOpen) return;
    const orig = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = orig;
    };
  }, [mobileOpen]);

  useEffect(() => {
    if (!userMenuOpen) return;
    const onDown = (e: MouseEvent) => {
      if (!userMenuRef.current?.contains(e.target as Node)) setUserMenuOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setUserMenuOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [userMenuOpen]);

  useEffect(() => {
    if (!mobileOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMobileOpen(false);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [mobileOpen]);

  const isModerator = user?.role === 'admin' || user?.role === 'moderator';

  const isActive = (href: string) =>
    href === '/' ? pathname === '/' : pathname === href || pathname.startsWith(href + '/');

  const handleLogout = async () => {
    setUserMenuOpen(false);
    setMobileOpen(false);
    try {
      await logout();
    } finally {
      router.replace('/login');
    }
  };

  const initials = useMemo(() => {
    const first = user?.name?.trim()?.[0] ?? '';
    return first ? first.toUpperCase() : '?';
  }, [user?.name]);

  const navItems = useMemo(() => NAV, []);

  return (
    <>
      {/* Skip-link */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-[100] focus:px-4 focus:py-2 focus:bg-[var(--accent-yellow)] focus:text-black focus:font-mono focus:text-[11px] focus:uppercase focus:tracking-[0.2em] focus:border focus:border-black"
      >
        К основному содержимому
      </a>

      <header className="sticky top-0 z-50 bg-[var(--bg-primary)]/90 backdrop-blur-md border-b border-[var(--line)]">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-10">
          <div className="flex items-center justify-between h-16 lg:h-[72px] gap-6">

            {/* ===== Бренд ===== */}
            <Link
              href="/"
              className="group flex items-center gap-2.5 shrink-0"
              aria-label="MovieTracker — на главную"
            >
              <FilmIcon
                className="w-5 h-5 text-[var(--accent-yellow)] transition-transform duration-500 group-hover:rotate-[-8deg]"
                aria-hidden="true"
              />
              <span className="font-serif text-xl tracking-[-0.02em] text-[var(--text-primary)] hidden sm:block">
                MovieTracker
                <span className="text-[var(--accent-yellow)]">.</span>
              </span>
            </Link>

            {/* ===== Десктопная навигация ===== */}
            <nav
              className="hidden md:flex items-center gap-7 flex-1 justify-center"
              aria-label="Основная навигация"
            >
              {navItems.map((item) => {
                const active = isActive(item.href);
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    aria-current={active ? 'page' : undefined}
                    className={`group relative font-mono text-[10px] uppercase tracking-[0.22em] transition-colors ${
                      active
                        ? 'text-[var(--text-primary)]'
                        : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                    }`}
                  >
                    {item.label}
                    <span
                      aria-hidden
                      className={`absolute -bottom-1.5 left-0 right-0 h-px origin-left transition-transform duration-500 ${
                        active
                          ? 'bg-[var(--accent-yellow)] scale-x-100'
                          : 'bg-[var(--text-primary)] scale-x-0 group-hover:scale-x-100'
                      }`}
                    />
                  </Link>
                );
              })}
            </nav>

            {/* Поиск — компактный, справа от навигации */}
            <div className="hidden md:block w-[220px] lg:w-[280px] shrink-0">
              <GlobalSearch />
            </div>

            {/* ===== Правая часть: модерация / профиль / бургер ===== */}
            <div className="flex items-center gap-3 shrink-0">
              {isModerator && (
                <Link
                  href="/moderation"
                  aria-current={isActive('/moderation') ? 'page' : undefined}
                  title="Панель модерации"
                  className={`hidden md:inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.22em] border-b pb-0.5 transition-colors ${
                    isActive('/moderation')
                      ? 'text-[var(--accent-red)] border-[var(--accent-red)]'
                      : 'text-[var(--text-muted)] border-transparent hover:text-[var(--accent-red)] hover:border-[var(--accent-red)]'
                  }`}
                >
                  <ShieldCheckIcon className="w-3.5 h-3.5" aria-hidden="true" />
                  Модерация
                </Link>
              )}

              {isAuthenticated && user ? (
                <div className="relative" ref={userMenuRef}>
                  <button
                    type="button"
                    onClick={() => setUserMenuOpen((v) => !v)}
                    aria-haspopup="menu"
                    aria-expanded={userMenuOpen}
                    aria-controls="user-menu"
                    className="group flex items-center gap-2.5"
                  >
                    <span
                      aria-hidden="true"
                      className="w-8 h-8 grid place-items-center bg-[var(--text-primary)] text-[var(--bg-primary)] font-serif text-sm transition-transform duration-500 group-hover:rotate-[-6deg]"
                    >
                      {initials}
                    </span>
                    <span className="hidden lg:block text-left leading-tight max-w-[140px]">
                      <span className="block font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)]">
                        @{user.login}
                      </span>
                    </span>
                  </button>

                  <AnimatePresence>
                    {userMenuOpen && (
                      <motion.div
                        id="user-menu"
                        role="menu"
                        initial={prefersReduced ? false : { opacity: 0, y: -6 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={prefersReduced ? undefined : { opacity: 0, y: -6 }}
                        transition={{ duration: 0.3, ease: EASE_OUT }}
                        className="absolute right-0 top-full mt-3 w-[260px] bg-[var(--bg-primary)] border border-[var(--line)] overflow-hidden"
                      >
                        <div className="px-5 py-4 border-b border-[var(--line)]">
                          <p className="font-serif text-base text-[var(--text-primary)] truncate">
                            {user.name}
                          </p>
                          <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)] truncate">
                            @{user.login}
                          </p>
                        </div>

                        <div className="py-1">
                          {[
                            { href: '/entries', label: 'Мои отметки' },
                            { href: '/lists', label: 'Мои списки' },
                            { href: '/profile', label: 'Профиль' },
                          ].map((item) => (
                            <Link
                              key={item.href}
                              href={item.href}
                              role="menuitem"
                              className="group flex items-center justify-between px-5 py-2.5 font-serif text-sm text-[var(--text-primary)] hover:bg-[var(--bg-secondary)] transition-colors"
                            >
                              <span className="group-hover:italic transition-[font-style] duration-300">
                                {item.label}
                              </span>
                              <ArrowUpRightIcon
                                className="w-3.5 h-3.5 text-[var(--text-muted)] opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                                aria-hidden="true"
                              />
                            </Link>
                          ))}
                        </div>

                        <div className="border-t border-[var(--line)] py-1">
                          <button
                            type="button"
                            role="menuitem"
                            onClick={handleLogout}
                            disabled={isLoading}
                            className="w-full flex items-center gap-2 px-5 py-2.5 font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)] hover:text-[var(--accent-red)] transition-colors disabled:opacity-60"
                          >
                            <ArrowRightOnRectangleIcon className="w-3.5 h-3.5" aria-hidden="true" />
                            {isLoading ? 'Выходим…' : 'Выйти'}
                          </button>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              ) : (
                <Link
                  href="/login"
                  className="hidden md:inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.22em] text-[var(--text-primary)] border-b border-[var(--text-primary)] pb-0.5 hover:border-[var(--accent-yellow)] transition-colors"
                >
                  Войти
                  <ArrowRightOnRectangleIcon className="w-3.5 h-3.5" aria-hidden="true" />
                </Link>
              )}

              {/* Бургер */}
              <button
                type="button"
                onClick={() => setMobileOpen((v) => !v)}
                aria-label={mobileOpen ? 'Закрыть меню' : 'Открыть меню'}
                aria-expanded={mobileOpen}
                aria-controls="mobile-nav"
                className="md:hidden inline-flex items-center justify-center w-9 h-9 text-[var(--text-primary)]"
              >
                {mobileOpen ? (
                  <XMarkIcon className="w-5 h-5" aria-hidden="true" />
                ) : (
                  <Bars3Icon className="w-5 h-5" aria-hidden="true" />
                )}
              </button>
            </div>
          </div>
        </div>

        {/* ===== Мобильное меню — fullscreen editorial ===== */}
        <AnimatePresence initial={false}>
          {mobileOpen && (
            <motion.div
              id="mobile-nav"
              initial={prefersReduced ? false : { opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={prefersReduced ? undefined : { opacity: 0 }}
              transition={{ duration: 0.3, ease: EASE_OUT }}
              className="md:hidden fixed inset-x-0 top-16 bottom-0 bg-[var(--bg-primary)] border-t border-[var(--line)] overflow-y-auto"
            >
              <div className="px-6 pt-8 pb-12">
                <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-6">
                  Навигация
                </p>

                <nav aria-label="Мобильная навигация">
                  <ul>
                    {navItems.map((item, i) => {
                      const active = isActive(item.href);
                      return (
                        <motion.li
                          key={item.href}
                          initial={prefersReduced ? false : { opacity: 0, x: -12 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{
                            duration: 0.4,
                            delay: i * 0.05,
                            ease: EASE_OUT,
                          }}
                          className="border-b border-[var(--line)]"
                        >
                          <Link
                            href={item.href}
                            aria-current={active ? 'page' : undefined}
                            className="group flex items-baseline justify-between py-5"
                          >
                            <span className="flex items-baseline gap-4">
                              <span className="font-mono text-[10px] tracking-[0.2em] text-[var(--text-muted)] min-w-[24px]">
                                {String(i + 1).padStart(2, '0')}
                              </span>
                              <span
                                className={`font-serif text-3xl leading-tight tracking-[-0.02em] transition-colors ${
                                  active
                                    ? 'text-[var(--text-primary)] italic'
                                    : 'text-[var(--text-primary)]'
                                }`}
                              >
                                {item.label}
                              </span>
                            </span>
                            {active && (
                              <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-yellow)]" />
                            )}
                          </Link>
                        </motion.li>
                      );
                    })}
                  </ul>
                </nav>

                {isModerator && (
                  <div className="mt-8">
                    <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)] mb-4">
                      Модератору
                    </p>
                    <Link
                      href="/moderation"
                      aria-current={isActive('/moderation') ? 'page' : undefined}
                      className="inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-[var(--accent-red)] border-b border-[var(--accent-red)] pb-0.5"
                    >
                      <ShieldCheckIcon className="w-3.5 h-3.5" aria-hidden="true" />
                      Панель модерации
                    </Link>
                  </div>
                )}

                <div className="mt-12 pt-8 border-t border-[var(--line)]">
                  {isAuthenticated && user ? (
                    <div className="flex items-center justify-between gap-4">
                      <div className="flex items-center gap-3 min-w-0">
                        <span
                          aria-hidden="true"
                          className="w-10 h-10 grid place-items-center bg-[var(--text-primary)] text-[var(--bg-primary)] font-serif text-base shrink-0"
                        >
                          {initials}
                        </span>
                        <div className="min-w-0">
                          <p className="font-serif text-base text-[var(--text-primary)] truncate">
                            {user.name}
                          </p>
                          <p className="font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--text-muted)] truncate">
                            @{user.login}
                          </p>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={handleLogout}
                        disabled={isLoading}
                        className="font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)] hover:text-[var(--accent-red)] border-b border-transparent hover:border-[var(--accent-red)] pb-0.5 transition-colors disabled:opacity-60 shrink-0"
                      >
                        {isLoading ? 'Выходим…' : 'Выйти'}
                      </button>
                    </div>
                  ) : (
                    <Link
                      href="/login"
                      className="group inline-flex items-center gap-3"
                    >
                      <span className="font-serif text-2xl italic text-[var(--text-primary)] group-hover:text-[var(--accent-yellow)] transition-colors">
                        Войти
                      </span>
                      <ArrowRightOnRectangleIcon
                        className="w-5 h-5 text-[var(--text-primary)]"
                        aria-hidden="true"
                      />
                    </Link>
                  )}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </header>
    </>
  );
}