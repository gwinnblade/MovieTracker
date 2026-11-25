"use client";

import Link from "next/link";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { api, errorMessage, safeNext } from "@/lib/api";
import { useAuth } from "./Auth";
import { Field } from "./UI";

export default function AuthForm({
  mode = "login",
}: {
  mode?: "login" | "register" | "forgot" | "reset";
}) {
  const router = useRouter();
  const search = useSearchParams();
  const params = useParams<{ token: string }>();
  const { setUser } = useAuth();
  const queries = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const titles = {
    login: "Рады видеть снова",
    register: "Твоя история начинается",
    forgot: "Восстановить пароль",
    reset: "Новый пароль",
  };
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const value = (key: string) => String(form.get(key) || "");
    setBusy(true);
    setError("");
    try {
      if (mode === "forgot") {
        setMessage((await api.forgot(value("email"))).message);
      } else if (mode === "reset") {
        const result = await api.reset({
          email: value("email"),
          token: params.token,
          password: value("password"),
          password_confirmation: value("password_confirmation"),
        });
        toast.success(result.message);
        router.push("/login");
      } else {
        const user =
          mode === "register"
            ? await api.register({
                name: value("name"),
                login: value("login"),
                email: value("email"),
                password: value("password"),
                password_confirmation: value("password_confirmation"),
              })
            : await api.login({
                login: value("login"),
                password: value("password"),
                remember: form.get("remember") === "on",
              });
        queries.clear();
        setUser(user);
        toast.success(
          mode === "register"
            ? "Аккаунт создан!"
            : `С возвращением, ${user.name}!`,
        );
        router.push(safeNext(search.get("next")));
      }
    } catch (error) {
      setError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="auth-panel panel">
      <span className="eyebrow">REWATCH</span>
      <h1>{titles[mode]}</h1>
      <p>
        {mode === "login"
          ? "Войди, чтобы продолжить свои истории."
          : mode === "register"
            ? "Сохраняй фильмы, оценки и любимые моменты."
            : "Верни доступ к своему дневнику кино."}
      </p>
      {message ? (
        <div className="notice" role="status">
          {message}
        </div>
      ) : (
        <form className="form-stack" onSubmit={submit}>
          {error && (
            <div className="notice error" role="alert">
              {error}
            </div>
          )}
          {mode === "register" && (
            <Field label="Как тебя зовут">
              <input name="name" autoComplete="name" required maxLength={100} />
            </Field>
          )}
          {(mode === "login" || mode === "register") && (
            <Field label={mode === "login" ? "Логин или email" : "Логин"}>
              <input
                name="login"
                autoComplete="username"
                required
                maxLength={50}
                minLength={mode === "register" ? 3 : undefined}
              />
            </Field>
          )}
          {mode !== "login" && (
            <Field label="Email">
              <input
                name="email"
                type="email"
                autoComplete="email"
                required
                defaultValue={mode === "reset" ? search.get("email") || "" : ""}
              />
            </Field>
          )}
          {mode !== "forgot" && (
            <Field label="Пароль">
              <input
                name="password"
                type="password"
                autoComplete={
                  mode === "login" ? "current-password" : "new-password"
                }
                required
                minLength={mode === "login" ? undefined : 8}
              />
            </Field>
          )}
          {(mode === "register" || mode === "reset") && (
            <Field label="Повтори пароль">
              <input
                name="password_confirmation"
                type="password"
                autoComplete="new-password"
                required
                minLength={8}
              />
            </Field>
          )}
          {mode === "login" && (
            <label className="check-label">
              <input name="remember" type="checkbox" />
              Запомнить меня
            </label>
          )}
          <button className="button" disabled={busy}>
            {busy
              ? "Подождите…"
              : mode === "login"
                ? "Войти"
                : mode === "register"
                  ? "Создать аккаунт"
                  : mode === "forgot"
                    ? "Отправить ссылку"
                    : "Изменить пароль"}
          </button>
        </form>
      )}
      <div className="auth-links">
        {mode === "login" ? (
          <>
            <Link href="/register">Создать аккаунт</Link>
            <Link href="/forgot-password">Забыли пароль?</Link>
          </>
        ) : (
          <Link href="/login">← Вернуться ко входу</Link>
        )}
      </div>
    </section>
  );
}
