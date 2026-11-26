"use client";

import Link from "next/link";
import {
  ArrowRightOnRectangleIcon,
  Bars3Icon,
  BookmarkSquareIcon,
  ChartBarIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  MagnifyingGlassIcon,
  UserCircleIcon,
  XMarkIcon,
} from "@heroicons/react/24/outline";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState, type FormEvent } from "react";
import toast from "react-hot-toast";
import { useAuth } from "./Auth";
import { errorMessage } from "@/lib/api";
import { Button, Input } from "./UI";

const accountLinks = [
  ["/profile", "Мой профиль", UserCircleIcon],
  ["/entries", "Мой список", BookmarkSquareIcon],
  ["/stats", "Статистика", ChartBarIcon],
] as const;

export default function Header() {
  const path = usePathname();
  const router = useRouter();
  const { user, loading, logout } = useAuth();
  const [menu, setMenu] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const accountRef = useRef<HTMLDivElement>(null);

  const nav = [
    ["/catalog", "Открыть кино"],
    ["/library", "Каталог"],
    ["/entries", "Мой список"],
    ["/collections", "Коллекции"],
    ["/stats", "Статистика"],
  ];

  const search = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const q = String(
      new FormData(event.currentTarget).get("query") || "",
    ).trim();
    if (q.length >= 2) {
      router.push("/search?q=" + encodeURIComponent(q));
      setMenu(false);
    }
  };

  useEffect(() => {
    document.body.style.overflow = menu ? "hidden" : "";
    return () => {
      document.body.style.overflow = "";
    };
  }, [menu]);

  useEffect(() => {
    setMenu(false);
    setDropdownOpen(false);
  }, [path]);

  useEffect(() => {
    const desktop = window.matchMedia("(min-width: 1280px)");
    const sync = () => {
      if (desktop.matches) setMenu(false);
    };
    desktop.addEventListener("change", sync);
    return () => desktop.removeEventListener("change", sync);
  }, []);

  useEffect(() => {
    if (!dropdownOpen) return;
    const outside = (event: MouseEvent) => {
      if (
        accountRef.current &&
        !accountRef.current.contains(event.target as Node)
      )
        setDropdownOpen(false);
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setDropdownOpen(false);
    };
    document.addEventListener("mousedown", outside);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("mousedown", outside);
      document.removeEventListener("keydown", escape);
    };
  }, [dropdownOpen]);

  const initials =
    user?.name
      ?.trim()
      .split(/\s+/)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase() || "")
      .join("") || "";

  const signOut = async () => {
    try {
      await logout();
      router.push("/");
    } catch (error) {
      toast.error(errorMessage(error));
    }
  };

  return (
    <>
      <header
        className={`site-header border-b border-white/[0.06]! transition-shadow duration-300 hover:shadow-[0_1px_0_0_rgba(229,169,61,0.15)] ${
          menu ? "z-20!" : ""
        }`}
      >
        <div className="header-inner">
          <Link
            href="/"
            className="brand group shrink-0"
            aria-label="Rewatch — главная"
          >
            <svg
              viewBox="0 0 32 32"
              aria-hidden="true"
              className="-rotate-6 transition-[filter,rotate] duration-300 group-hover:rotate-0 group-hover:drop-shadow-[0_0_8px_rgba(229,169,61,0.6)]"
            >
              <path d="M25 10a11 11 0 1 0 1 11M25 3v8h-8" />
              <path d="m13 10 9 6-9 6z" />
            </svg>
            Rewatch<span className="brand-dot">.</span>
          </Link>

          <nav
            aria-label="Главное меню"
            className="hidden min-w-0 flex-1 items-center gap-1 xl:flex"
          >
            {nav.map(([href, text]) => (
              <Link
                key={href}
                href={href}
                className={
                  path.startsWith(href)
                    ? "inline-flex items-center gap-2 rounded-lg border border-gold/20 bg-gold/10 px-3 py-1.5 text-xs font-semibold whitespace-nowrap text-gold! before:size-1 before:rounded-full before:bg-gold before:content-['']"
                    : "inline-flex items-center rounded-lg border border-transparent px-3 py-1.5 text-xs font-semibold whitespace-nowrap text-zinc-400! transition-colors duration-200 hover:bg-white/[0.03] hover:text-white!"
                }
              >
                {text}
              </Link>
            ))}
          </nav>

          <div className="hidden shrink-0 items-center gap-2 xl:flex">
            <form
              onSubmit={search}
              role="search"
              className="group/search relative w-56 rounded-xl transition-[width,box-shadow] duration-300 focus-within:w-72 focus-within:shadow-[0_0_15px_rgba(229,169,61,0.15)]"
            >
              <MagnifyingGlassIcon
                className="pointer-events-none absolute top-1/2 left-3.5 size-4 -translate-y-1/2 text-zinc-500 transition-colors duration-200 group-focus-within/search:text-gold"
                aria-hidden="true"
              />
              <Input
                name="query"
                placeholder="Найти фильм..."
                aria-label="Поиск по TMDB"
                minLength={2}
                required
                className="min-h-11! rounded-xl! bg-white/[0.03]! pr-11! pl-10! text-[13px]! focus:ring-0!"
              />
              <button
                type="submit"
                aria-label="Искать"
                className="absolute top-1/2 right-1.5 grid size-8 -translate-y-1/2 place-items-center rounded-lg text-zinc-500 transition-colors duration-200 hover:bg-gold/10 hover:text-gold focus-visible:text-gold"
              >
                <MagnifyingGlassIcon className="size-4" aria-hidden="true" />
              </button>
            </form>

            {!loading &&
              (user ? (
                <div ref={accountRef} className="relative">
                  <button
                    type="button"
                    aria-haspopup="menu"
                    aria-expanded={dropdownOpen}
                    onClick={() => setDropdownOpen((open) => !open)}
                    className="flex min-h-11 items-center gap-2 rounded-xl px-3 py-2 text-zinc-200 transition-colors duration-200 hover:bg-white/[0.05]"
                  >
                    <span className="grid size-8 shrink-0 place-items-center rounded-full border border-gold/30 bg-gold/10 text-[11px] font-bold text-gold">
                      {initials || (
                        <UserCircleIcon className="size-5" aria-hidden="true" />
                      )}
                    </span>
                    <span className="max-w-24 truncate text-[13px] font-semibold">
                      {user.name}
                    </span>
                    <ChevronDownIcon
                      className={`size-3.5 shrink-0 text-zinc-500 transition-transform duration-300 ${
                        dropdownOpen ? "rotate-180" : ""
                      }`}
                      aria-hidden="true"
                    />
                  </button>

                  <div
                    role="menu"
                    aria-hidden={!dropdownOpen}
                    className={`absolute top-full right-0 z-50 mt-2 w-56 origin-top-right rounded-2xl border border-white/10 bg-[#151921]/95 p-2 shadow-[0_20px_60px_rgba(0,0,0,0.5)] backdrop-blur-xl transition-[opacity,scale,visibility] duration-200 ${
                      dropdownOpen
                        ? "visible scale-100 opacity-100"
                        : "invisible scale-95 opacity-0"
                    }`}
                  >
                    <div className="px-3 py-2">
                      <span className="block text-[10px] font-bold tracking-[0.19em] text-gold uppercase">
                        Аккаунт
                      </span>
                      <span className="mt-0.5 block truncate text-[13px] font-semibold text-white">
                        {user.name}
                      </span>
                    </div>
                    <div className="my-1 border-t border-white/5" />
                    {accountLinks.map(([href, label, Icon]) => (
                      <Link
                        key={href}
                        href={href}
                        role="menuitem"
                        onClick={() => setDropdownOpen(false)}
                        className="flex min-h-11 items-center gap-3 rounded-xl px-3 text-[13px] font-medium text-zinc-300! transition-colors duration-200 hover:bg-white/[0.05] hover:text-white!"
                      >
                        <Icon
                          className="size-4 shrink-0 text-zinc-500"
                          aria-hidden="true"
                        />
                        {label}
                      </Link>
                    ))}
                    <div className="my-1 border-t border-white/5" />
                    <Button
                      variant="ghost"
                      role="menuitem"
                      className="min-h-11! w-full justify-start! gap-3! rounded-xl! px-3! py-2! text-[13px]! font-medium! text-red-400! enabled:hover:bg-red-500/10! enabled:hover:text-red-300!"
                      onClick={() => {
                        setDropdownOpen(false);
                        void signOut();
                      }}
                    >
                      <ArrowRightOnRectangleIcon
                        className="size-4 shrink-0"
                        aria-hidden="true"
                      />
                      Выйти
                    </Button>
                  </div>
                </div>
              ) : (
                <Link className="button shrink-0" href="/login">
                  Войти
                </Link>
              ))}
          </div>

          <button
            type="button"
            aria-label="Меню"
            aria-expanded={menu}
            onClick={() => setMenu(!menu)}
            className="ml-auto grid size-11 shrink-0 place-items-center rounded-full border border-white/10 bg-white/[0.03] text-zinc-300 transition-colors duration-200 hover:bg-white/[0.08] hover:text-white xl:hidden"
          >
            {menu ? (
              <XMarkIcon className="size-5" aria-hidden="true" />
            ) : (
              <Bars3Icon className="size-5" aria-hidden="true" />
            )}
          </button>
        </div>
      </header>

      <div
        onClick={() => setMenu(false)}
        aria-hidden="true"
        className={`fixed inset-0 z-30 bg-black/60 backdrop-blur-sm transition-opacity duration-300 xl:hidden ${
          menu ? "opacity-100" : "pointer-events-none opacity-0"
        }`}
      />

      <aside
        aria-label="Мобильное меню"
        aria-hidden={!menu}
        className={`fixed top-0 right-0 z-40 flex h-full w-[85vw] max-w-sm flex-col gap-6 overflow-hidden border-l border-white/10 bg-[#0B0E14] p-6 transition-[transform,visibility] duration-300 xl:hidden ${
          menu ? "visible translate-x-0" : "invisible translate-x-full"
        }`}
      >
        <div
          className="pointer-events-none absolute -top-20 left-1/2 size-64 -translate-x-1/2 rounded-full bg-gold/10 blur-3xl"
          aria-hidden="true"
        />

        <div className="relative flex shrink-0 items-center justify-between">
          <span className="eyebrow">Навигация</span>
          <button
            type="button"
            aria-label="Закрыть меню"
            onClick={() => setMenu(false)}
            className="grid size-11 place-items-center rounded-full border border-white/10 bg-white/[0.03] text-zinc-300 transition-colors duration-200 hover:bg-white/[0.08] hover:text-white"
          >
            <XMarkIcon className="size-5" aria-hidden="true" />
          </button>
        </div>

        <nav
          aria-label="Главное меню"
          className="relative -mt-2 flex min-h-0 flex-1 flex-col overflow-y-auto"
        >
          {nav.map(([href, text]) => (
            <Link
              key={href}
              href={href}
              onClick={() => setMenu(false)}
              className={`flex min-h-14 items-center justify-between gap-3 border-b border-white/5 py-3 text-xl font-semibold transition-colors duration-200 ${
                path.startsWith(href)
                  ? "text-gold!"
                  : "text-zinc-300! hover:text-white!"
              }`}
            >
              <span className="flex items-center gap-3">
                {path.startsWith(href) && (
                  <span
                    className="size-1.5 shrink-0 rounded-full bg-gold shadow-[0_0_8px_rgba(229,169,61,0.8)]"
                    aria-hidden="true"
                  />
                )}
                {text}
              </span>
              <ChevronRightIcon
                className="size-4 shrink-0 text-zinc-600"
                aria-hidden="true"
              />
            </Link>
          ))}
        </nav>

        <form
          onSubmit={search}
          role="search"
          className="group/mobile relative shrink-0"
        >
          <MagnifyingGlassIcon
            className="pointer-events-none absolute top-1/2 left-4 size-4 -translate-y-1/2 text-zinc-500 transition-colors duration-200 group-focus-within/mobile:text-gold"
            aria-hidden="true"
          />
          <Input
            name="query"
            placeholder="Найти фильм..."
            aria-label="Поиск по TMDB"
            minLength={2}
            required
            className="min-h-12! rounded-xl! bg-white/[0.03]! pr-14! pl-11! focus:ring-0!"
          />
          <button
            type="submit"
            aria-label="Искать"
            className="absolute top-1/2 right-1.5 grid size-9 -translate-y-1/2 place-items-center rounded-lg text-zinc-500 transition-colors duration-200 hover:bg-gold/10 hover:text-gold"
          >
            <MagnifyingGlassIcon className="size-4" aria-hidden="true" />
          </button>
        </form>

        <div className="relative shrink-0">
          {!loading &&
            (user ? (
              <div className="flex flex-col gap-3">
                <Link
                  href="/profile"
                  onClick={() => setMenu(false)}
                  className="flex min-h-12 items-center gap-3 rounded-xl border border-white/5 bg-white/[0.02] px-3 text-zinc-200! transition-colors duration-200 hover:bg-white/[0.05]"
                >
                  <span className="grid size-8 shrink-0 place-items-center rounded-full border border-gold/30 bg-gold/10 text-[11px] font-bold text-gold">
                    {initials || (
                      <UserCircleIcon className="size-5" aria-hidden="true" />
                    )}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-sm font-semibold">
                    {user.name}
                  </span>
                  <ChevronRightIcon
                    className="size-4 shrink-0 text-zinc-600"
                    aria-hidden="true"
                  />
                </Link>
                <Button
                  variant="ghost"
                  className="min-h-12! w-full justify-start! gap-3! rounded-xl! border-white/5! px-3! text-sm! font-medium! text-red-400! enabled:hover:bg-red-500/10! enabled:hover:text-red-300!"
                  onClick={() => {
                    setMenu(false);
                    void signOut();
                  }}
                >
                  <ArrowRightOnRectangleIcon
                    className="size-4 shrink-0"
                    aria-hidden="true"
                  />
                  Выйти
                </Button>
              </div>
            ) : (
              <Link
                href="/login"
                onClick={() => setMenu(false)}
                className="button w-full"
              >
                Войти в аккаунт
              </Link>
            ))}
        </div>
      </aside>
    </>
  );
}