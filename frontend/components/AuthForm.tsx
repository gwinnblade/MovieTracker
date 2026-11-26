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
    <section className="relative mx-auto my-9 w-full max-w-[460px] overflow-hidden rounded-3xl border border-white/5 bg-[#151921]/80 p-6 shadow-[0_0_50px_rgba(229,169,61,0.05),0_24px_60px_rgba(0,0,0,0.45)] backdrop-blur-xl sm:p-10">
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-[3px] bg-gradient-to-r from-gold/0 via-gold to-gold/0"
        aria-hidden="true"
      />
      <div
        className="pointer-events-none absolute -top-24 left-1/2 h-48 w-80 -translate-x-1/2 rounded-full bg-gold/10 blur-3xl"
        aria-hidden="true"
      />
      <div className="relative mb-8 flex flex-col gap-3">
        <span className="eyebrow">REWATCH</span>
        <h1 className="text-3xl! font-bold! tracking-tight! text-white">
          {titles[mode]}
        </h1>
        <p className="text-sm leading-relaxed text-zinc-400">
          {mode === "login"
            ? "Войди, чтобы продолжить свои истории."
            : mode === "register"
              ? "Сохраняй фильмы, оценки и любимые моменты."
              : "Верни доступ к своему дневнику кино."}
        </p>
      </div>
      {message ? (
        <div className="notice relative" role="status">
          {message}
        </div>
      ) : (
        <form className="form-stack relative" onSubmit={submit}>
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
      <div className="auth-links relative">
        {mode === "login" ? (
          <>
            <Link
              href="/register"
              className="text-zinc-400 hover:text-gold transition-colors duration-200"
            >
              Создать аккаунт
            </Link>
            <Link
              href="/forgot-password"
              className="text-zinc-400 hover:text-gold transition-colors duration-200"
            >
              Забыли пароль?
            </Link>
          </>
        ) : (
          <Link
            href="/login"
            className="group inline-flex items-center gap-1.5 text-zinc-400 hover:text-gold transition-colors duration-200"
          >
            <ArrowLeftIcon
              className="ui-icon transition-transform duration-200 group-hover:-translate-x-0.5"
              aria-hidden="true"
            />{" "}
            Вернуться ко входу
          </Link>
        )}
      </div>
    </section>
  );
}