"use client";
import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowRightIcon, FilmIcon } from "@heroicons/react/24/outline";
import { api } from "@/lib/api";
import type { User } from "@/lib/types";
import { Loading } from "./UI";

interface AuthState {
  user: User | null;
  loading: boolean;
  setUser: (user: User | null) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const queries = useQueryClient();

  useEffect(() => {
    let active = true;
    api
      .me()
      .then((u) => {
        if (active) setUser(u);
      })
      .catch(() => {
        if (active) setUser(null);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const logout = async () => {
    await api.logout();
    setUser(null);
    queries.clear();
  };

  return (
    <AuthContext.Provider value={{ user, loading, setUser, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("AuthProvider is missing");
  return value;
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const path = usePathname();

  if (loading) return <Loading text="Загрузка аккаунта…" />;

  if (!user)
    return (
      <div className="relative mx-auto mt-20 max-w-2xl border-2 border-white/20 bg-[var(--panel)] p-12 text-center shadow-[12px_12px_0px_0px_var(--accent)]">
        <div className="absolute -top-4 left-1/2 -translate-x-1/2 border-2 border-[var(--bg)] bg-[var(--accent)] px-4 py-1 font-mono text-xs font-bold uppercase tracking-widest text-[var(--bg)]">
          [ Доступ ограничен ]
        </div>
        
        <div className="relative flex flex-col items-center">
          <span className="mb-8 inline-flex size-16 items-center justify-center border-2 border-[var(--bg)] bg-[var(--accent)] text-[var(--bg)] shadow-[6px_6px_0px_0px_var(--text)]">
            <FilmIcon className="size-8" aria-hidden="true" />
          </span>
          
          <h1 className="text-4xl font-black uppercase leading-tight tracking-tighter text-[var(--text)] sm:text-5xl">
            Всё любимое <br />
            <span className="inline-block bg-[var(--accent)] px-3 text-[var(--bg)]">
              в одном месте
            </span>
          </h1>
          
          <p className="mx-auto mt-6 max-w-md text-base leading-relaxed text-[var(--muted)]">
            Войди, чтобы вести список просмотров, собирать коллекции и отправлять заявки. Никаких алгоритмов — только твой личный дневник кино.
          </p>
          
          <div className="mt-10 flex w-full max-w-sm flex-col gap-4">
            <Link
              href={"/login?next=" + encodeURIComponent(path)}
              className="group inline-flex items-center justify-center gap-3 border-2 border-[var(--accent)] bg-[var(--accent)] px-6 py-4 text-sm font-bold uppercase tracking-wider text-[var(--bg)] shadow-[6px_6px_0px_0px_var(--text)] transition-all hover:translate-x-[-2px] hover:translate-y-[-2px] hover:shadow-[8px_8px_0px_0px_var(--text)] active:translate-x-0 active:translate-y-0 active:shadow-none"
            >
              Войти в аккаунт
              <ArrowRightIcon className="h-5 w-5 transition-transform group-hover:translate-x-1" />
            </Link>
            <Link
              href="/register"
              className="inline-flex items-center justify-center gap-3 border-2 border-white/20 bg-transparent px-6 py-4 text-sm font-bold uppercase tracking-wider text-[var(--text)] shadow-[6px_6px_0px_0px_rgba(255,255,255,0.1)] transition-all hover:translate-x-[-2px] hover:translate-y-[-2px] hover:border-white/40 hover:shadow-[8px_8px_0px_0px_rgba(255,255,255,0.15)] active:translate-x-0 active:translate-y-0 active:shadow-none"
            >
              Создать аккаунт
            </Link>
          </div>
        </div>
      </div>
    );

  return children;
}