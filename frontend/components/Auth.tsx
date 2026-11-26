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
import { FilmIcon } from "@heroicons/react/24/outline";
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
      <div className="relative mx-auto mt-20 max-w-2xl overflow-hidden rounded-3xl border border-white/5 bg-[#151921] p-12 text-center shadow-[0_0_80px_rgba(229,169,61,0.06),0_30px_80px_rgba(0,0,0,0.5)]">
        <div
          className="pointer-events-none absolute -top-28 left-1/2 h-64 w-96 -translate-x-1/2 rounded-full bg-gold/10 blur-3xl"
          aria-hidden="true"
        />
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-gold/60 to-transparent"
          aria-hidden="true"
        />
        <div className="relative">
          <span className="mx-auto mb-7 grid size-14 place-items-center rounded-2xl border border-gold/20 bg-gold/10 text-gold shadow-[0_0_30px_rgba(229,169,61,0.18)]">
            <FilmIcon className="size-6" aria-hidden="true" />
          </span>
          <span className="eyebrow">ТВОЯ БИБЛИОТЕКА</span>
          <div className="mt-3">
            <h1>Всё любимое — в одном месте</h1>
          </div>
          <div className="mx-auto mt-4 max-w-md">
            <p className="text-sm leading-relaxed text-zinc-400">
              Войди, чтобы вести список просмотров, собирать коллекции и
              отправлять заявки.
            </p>
          </div>
          <div className="mx-auto mt-9 flex w-full max-w-xs flex-col gap-3">
            <Link
              href={"/login?next=" + encodeURIComponent(path)}
              className="button primary w-full"
            >
              Войти в аккаунт
            </Link>
            <Link href="/register" className="button secondary w-full">
              Создать аккаунт
            </Link>
          </div>
        </div>
      </div>
    );

  return children;
}