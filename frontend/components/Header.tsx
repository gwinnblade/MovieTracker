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
import { Button, Input, Artwork } from "./UI";

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
        className={`site-header sticky top-0 z-40 border-b-2 border-white/10 bg-[var(--bg)] ${
          menu ? "z-50" : ""
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
              className="-rotate-6 transition-transform duration-150 group-hover:rotate-0"
            >
              <path d="M25 10a11 11 0 1 0 1 11M25 3v8h-8" />
              <path d="m13 10 9 6-9 6z" />
            </svg>
            Rewatch<span className="brand-dot">.</span>
          </Link>

          <nav
            aria-label="Главное меню"
            className="hidden min-w-0 flex-1 items-center gap-0 xl:flex"
          >
            {nav.map(([href, text]) => {
              const isActive = path.startsWith(href);
              return (
                <Link
                  key={href}
                  href={href}
                  className={
          isActive
            ? "inline-flex items-center border-2 border-[var(--accent)] bg-[var(--accent)] px-3 py-1.5 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)]! shadow-[3px_3px_0px_0px_var(--text)]"
            : "inline-flex items-center border-2 border-transparent px-3 py-1.5 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--muted)] transition-colors duration-150 hover:border-white/20 hover:text-[var(--text)]"
        }
                >
                  {text}
                </Link>
              );
            })}
          </nav>

          <div className="hidden shrink-0 items-center gap-3 xl:flex">
            <form
              onSubmit={search}
              role="search"
              className="group/search relative w-56 transition-[width] duration-150 focus-within:w-72"
            >
              <MagnifyingGlassIcon
                className="pointer-events-none absolute top-1/2 left-3.5 size-4 -translate-y-1/2 text-[var(--subtle)] transition-colors duration-150 group-focus-within/search:text-[var(--accent)]"
                aria-hidden="true"
              />
              <Input
                name="query"
                placeholder="Найти фильм..."
                aria-label="Поиск по TMDB"
                minLength={2}
                required
                className="min-h-11! border-2! border-white/10! bg-[var(--panel)]! pr-11! pl-10! text-[13px]! focus:border-[var(--accent)]! focus:ring-0!"
              />
              <button
                type="submit"
                aria-label="Искать"
                className="absolute top-1/2 right-1.5 grid size-8 -translate-y-1/2 place-items-center text-[var(--subtle)] transition-colors duration-150 hover:bg-[var(--accent)] hover:text-[var(--bg)]"
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
                    className="flex min-h-11 items-center gap-2 border-2 border-white/10 bg-[var(--panel)] px-3 py-2 transition-colors duration-150 hover:border-white/30"
                  >
                    {user.avatar_url ? (
                      <Artwork
                        src={user.avatar_url}
                        alt={user.name}
                        className="size-8 shrink-0 border-2 border-[var(--accent)]"
                      />
                    ) : (
                      <span className="grid size-8 shrink-0 place-items-center border-2 border-[var(--accent)] bg-[var(--accent)] font-mono text-[11px] font-black uppercase text-[var(--bg)]">
                        {initials || (
                          <UserCircleIcon className="size-5" aria-hidden="true" />
                        )}
                      </span>
                    )}
                    <span className="max-w-24 truncate font-mono text-[11px] font-black uppercase tracking-widest text-[var(--text)]">
                      {user.name}
                    </span>
                    <ChevronDownIcon
                      className={`size-3.5 shrink-0 text-[var(--muted)] transition-transform duration-150 ${
                        dropdownOpen ? "rotate-180" : ""
                      }`}
                      aria-hidden="true"
                    />
                  </button>

                  <div
                    role="menu"
                    aria-hidden={!dropdownOpen}
                    className={`absolute top-full right-0 z-50 mt-2 w-60 border-2 border-white/10 bg-[var(--panel)] shadow-[8px_8px_0px_0px_var(--accent)] transition-[opacity,transform,visibility] duration-150 ${
                      dropdownOpen
                        ? "visible translate-y-0 opacity-100"
                        : "invisible -translate-y-2 opacity-0"
                    }`}
                  >
                    <div className="border-b-2 border-white/10 px-4 py-3">
                      <span className="block font-mono text-[10px] font-black uppercase tracking-widest text-[var(--accent)]">
                        [ Аккаунт ]
                      </span>
                      <span className="mt-1 block truncate font-mono text-[13px] font-black uppercase tracking-tight text-[var(--text)]">
                        {user.name}
                      </span>
                    </div>
                    {accountLinks.map(([href, label, Icon]) => (
                      <Link
                        key={href}
                        href={href}
                        role="menuitem"
                        onClick={() => setDropdownOpen(false)}
                        className="flex min-h-11 items-center gap-3 border-b-2 border-white/5 px-4 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--muted)] transition-colors duration-150 hover:bg-white/5 hover:text-[var(--text)] last:border-b-0"
                      >
                        <Icon
                          className="size-4 shrink-0 text-[var(--subtle)]"
                          aria-hidden="true"
                        />
                        {label}
                      </Link>
                    ))}
                    <div className="p-2">
                      <Button
                        variant="ghost"
                        role="menuitem"
                        className="min-h-11! w-full justify-start! gap-3! border-2! border-transparent! px-3! py-2! font-mono! text-[11px]! font-black! uppercase! tracking-widest! text-[var(--red)]! hover:border-[var(--red)]! hover:bg-[var(--red)]/10!"
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
                </div>
              ) : (
                <Link
                  className="inline-flex items-center border-2 border-[var(--accent)] bg-[var(--accent)] px-5 py-2.5 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)] shadow-[4px_4px_0px_0px_var(--text)] transition-all hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[6px_6px_0px_0px_var(--text)] active:translate-x-0 active:translate-y-0 active:shadow-none"
                  href="/login"
                >
                  Войти
                </Link>
              ))}
          </div>

          <button
            type="button"
            aria-label="Меню"
            aria-expanded={menu}
            onClick={() => setMenu(!menu)}
            className="ml-auto grid size-11 shrink-0 place-items-center border-2 border-white/10 bg-[var(--panel)] text-[var(--text)] transition-colors duration-150 hover:border-[var(--accent)] hover:text-[var(--accent)] xl:hidden"
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
        className={`fixed inset-0 z-30 bg-black/80 transition-opacity duration-150 xl:hidden ${
          menu ? "opacity-100" : "pointer-events-none opacity-0"
        }`}
      />

      <aside
        aria-label="Мобильное меню"
        aria-hidden={!menu}
        className={`fixed top-0 right-0 z-40 flex h-full w-[85vw] max-w-sm flex-col gap-6 overflow-hidden border-l-2 border-white/10 bg-[var(--bg)] p-6 transition-[transform,visibility] duration-150 xl:hidden ${
          menu ? "visible translate-x-0" : "invisible translate-x-full"
        }`}
      >
        <div className="relative flex shrink-0 items-center justify-between border-b-2 border-white/10 pb-4">
          <span className="inline-block border-2 border-[var(--accent)] bg-[var(--accent)] px-3 py-1 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)]">
            [ Навигация ]
          </span>
          <button
            type="button"
            aria-label="Закрыть меню"
            onClick={() => setMenu(false)}
            className="grid size-11 place-items-center border-2 border-white/10 bg-[var(--panel)] text-[var(--text)] transition-colors duration-150 hover:border-[var(--accent)] hover:text-[var(--accent)]"
          >
            <XMarkIcon className="size-5" aria-hidden="true" />
          </button>
        </div>

        <nav
          aria-label="Главное меню"
          className="relative -mt-2 flex min-h-0 flex-1 flex-col overflow-y-auto"
        >
          {nav.map(([href, text]) => {
            const isActive = path.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                onClick={() => setMenu(false)}
                className={
                  isActive
                    ? "flex min-h-14 items-center justify-between gap-3 border-b-2 border-white/10 py-3 font-mono text-[13px] font-black uppercase tracking-widest text-[var(--bg)]"
                    : "flex min-h-14 items-center justify-between gap-3 border-b-2 border-white/10 py-3 font-mono text-[13px] font-black uppercase tracking-widest text-[var(--muted)] transition-colors duration-150 hover:text-[var(--text)]"
                }
              >
                <span className="flex items-center gap-3">
                  {isActive && (
                    <span
                      className="size-3 shrink-0 bg-[var(--accent)]"
                      aria-hidden="true"
                    />
                  )}
                  {text}
                </span>
                {isActive ? (
                  <span className="inline-block border-2 border-[var(--bg)] bg-[var(--accent)] px-2 py-0.5 font-mono text-[10px] font-black uppercase tracking-widest text-[var(--bg)] shadow-[2px_2px_0px_0px_var(--text)]">
                    Active
                  </span>
                ) : (
                  <ChevronRightIcon
                    className="size-4 shrink-0 text-[var(--subtle)]"
                    aria-hidden="true"
                  />
                )}
              </Link>
            );
          })}
        </nav>

        <form
          onSubmit={search}
          role="search"
          className="group/mobile relative shrink-0"
        >
          <MagnifyingGlassIcon
            className="pointer-events-none absolute top-1/2 left-4 size-4 -translate-y-1/2 text-[var(--subtle)] transition-colors duration-150 group-focus-within/mobile:text-[var(--accent)]"
            aria-hidden="true"
          />
          <Input
            name="query"
            placeholder="Найти фильм..."
            aria-label="Поиск по TMDB"
            minLength={2}
            required
            className="min-h-12! border-2! border-white/10! bg-[var(--panel)]! pr-14! pl-11! focus:border-[var(--accent)]! focus:ring-0!"
          />
          <button
            type="submit"
            aria-label="Искать"
            className="absolute top-1/2 right-1.5 grid size-9 -translate-y-1/2 place-items-center text-[var(--subtle)] transition-colors duration-150 hover:bg-[var(--accent)] hover:text-[var(--bg)]"
          >
            <MagnifyingGlassIcon className="size-4" aria-hidden="true" />
          </button>
        </form>

        <div className="relative shrink-0 border-t-2 border-white/10 pt-4">
          {!loading &&
            (user ? (
              <div className="flex flex-col gap-3">
                <Link
                  href="/profile"
                  onClick={() => setMenu(false)}
                  className="flex min-h-12 items-center gap-3 border-2 border-white/10 bg-[var(--panel)] px-3 transition-colors duration-150 hover:border-[var(--accent)]"
                >
                  {user.avatar_url ? (
                    <Artwork
                      src={user.avatar_url}
                      alt={user.name}
                      className="size-8 shrink-0 border-2 border-[var(--accent)]"
                    />
                  ) : (
                    <span className="grid size-8 shrink-0 place-items-center border-2 border-[var(--accent)] bg-[var(--accent)] font-mono text-[11px] font-black uppercase text-[var(--bg)]">
                      {initials || (
                        <UserCircleIcon className="size-5" aria-hidden="true" />
                      )}
                    </span>
                  )}
                  <span className="min-w-0 flex-1 truncate font-mono text-[11px] font-black uppercase tracking-widest text-[var(--text)]">
                    {user.name}
                  </span>
                  <ChevronRightIcon
                    className="size-4 shrink-0 text-[var(--subtle)]"
                    aria-hidden="true"
                  />
                </Link>
                <Button
                  variant="ghost"
                  className="min-h-12! w-full justify-start! gap-3! border-2! border-transparent! px-3! font-mono! text-[11px]! font-black! uppercase! tracking-widest! text-[var(--red)]! hover:border-[var(--red)]! hover:bg-[var(--red)]/10!"
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
                className="inline-flex w-full items-center justify-center border-2 border-[var(--accent)] bg-[var(--accent)] px-5 py-3 font-mono text-[11px] font-black uppercase tracking-widest text-[var(--bg)] shadow-[4px_4px_0px_0px_var(--text)] transition-all hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[6px_6px_0px_0px_var(--text)] active:translate-x-0 active:translate-y-0 active:shadow-none"
              >
                Войти в аккаунт
              </Link>
            ))}
        </div>
      </aside>
    </>
  );
}