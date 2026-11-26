"use client";
import { ArrowLeftIcon } from "@heroicons/react/24/outline";
import Link from "next/link";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { api, errorMessage, safeNext } from "@/lib/api";
import { useAuth } from "./Auth";
import { Button, Checkbox, Field, Input } from "./UI";

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
    <section className="relative mx-auto my-12 w-full max-w-[460px] border-2 border-white/20 bg-[var(--panel)] shadow-[12px_12px_0px_0px_var(--accent)]">
      {/* Solid accent bar — ticket stub edge */}
      <div
        className="absolute inset-x-0 top-0 h-1 bg-[var(--accent)]"
        aria-hidden="true"
      />

      {/* Stamp-like brand label */}
      <div className="relative border-b-2 border-white/10 px-8 pt-8 pb-6 sm:px-10 sm:pt-10">
        <span className="inline-block border-2 border-[var(--accent)] bg-[var(--accent)] px-3 py-1 font-mono text-xs font-black uppercase tracking-widest text-[var(--bg)]">
          [ REWATCH ]
        </span>
        <h1 className="mt-5 text-3xl font-black uppercase leading-[1.05] tracking-tighter text-[var(--text)] sm:text-4xl">
          {titles[mode]}
        </h1>
        <p className="mt-3 max-w-sm text-sm text-[var(--muted)]">
          {mode === "login"
            ? "Войди, чтобы продолжить свои истории."
            : mode === "register"
              ? "Сохраняй фильмы, оценки и любимые моменты."
              : "Верни доступ к своему дневнику кино."}
        </p>
      </div>

      <div className="relative px-8 py-8 sm:px-10 sm:py-10">
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
                <Input name="name" autoComplete="name" required maxLength={100} />
              </Field>
            )}

            {(mode === "login" || mode === "register") && (
              <Field label={mode === "login" ? "Логин или email" : "Логин"}>
                <Input
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
                <Input
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
                <Input
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
                <Input
                  name="password_confirmation"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={8}
                />
              </Field>
            )}

            {mode === "login" && (
              <label className="check-label select-none">
                <Checkbox name="remember" />
                Запомнить меня
              </label>
            )}

            <Button variant="primary" disabled={busy} className="w-full">
              {busy
                ? "Подождите…"
                : mode === "login"
                  ? "Войти"
                  : mode === "register"
                    ? "Создать аккаунт"
                    : mode === "forgot"
                      ? "Отправить ссылку"
                      : "Изменить пароль"}
            </Button>
          </form>
        )}

        <div className="auth-links mt-8 border-t-2 border-white/10 pt-6">
          {mode === "login" ? (
            <>
              <Link
                href="/register"
                className="font-mono text-xs uppercase tracking-widest text-[var(--muted)] hover:text-[var(--accent)]"
              >
                [ Создать аккаунт ]
              </Link>
              <Link
                href="/forgot-password"
                className="font-mono text-xs uppercase tracking-widest text-[var(--muted)] hover:text-[var(--accent)]"
              >
                [ Забыли пароль? ]
              </Link>
            </>
          ) : (
            <Link
              href="/login"
              className="group inline-flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-[var(--muted)] hover:text-[var(--accent)]"
            >
              <ArrowLeftIcon className="ui-icon" aria-hidden="true" />
              Вернуться ко входу
            </Link>
          )}
        </div>
      </div>
    </section>
  );
}