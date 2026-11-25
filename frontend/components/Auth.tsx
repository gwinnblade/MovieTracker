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
import { api } from "@/lib/api";
import type { User } from "@/lib/types";

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
  if (loading)
    return (
      <div className="loading" role="status">
        Загрузка аккаунта…
      </div>
    );
  if (!user)
    return (
      <div className="empty-state panel">
        <span className="eyebrow">ТВОЯ БИБЛИОТЕКА</span>
        <h1>Всё любимое — в одном месте</h1>
        <p>
          Войди, чтобы вести список просмотров, собирать коллекции и отправлять
          заявки.
        </p>
        <Link
          className="button"
          href={"/login?next=" + encodeURIComponent(path)}
        >
          Войти в аккаунт
        </Link>
        <Link href="/register">Создать аккаунт</Link>
      </div>
    );
  return children;
}
