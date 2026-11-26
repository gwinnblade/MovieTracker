"use client";

import { ArrowPathIcon, HomeIcon, ExclamationTriangleIcon } from "@heroicons/react/24/outline";
import Link from "next/link";
import { Button } from "@/components/UI";

export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="mx-auto mt-20 max-w-xl px-4">
      <div className="relative overflow-hidden rounded-3xl border border-white/5 bg-gradient-to-br from-[#151921] to-[#0B0E14] p-8 text-center shadow-[0_30px_80px_rgba(0,0,0,0.5)] sm:p-10">
        <div
          className="pointer-events-none absolute -top-32 left-1/2 size-64 -translate-x-1/2 rounded-full bg-red-500/10 blur-3xl"
          aria-hidden="true"
        />
        <div className="relative">
          <span className="mx-auto mb-6 grid size-16 place-items-center rounded-2xl border border-red-500/20 bg-red-500/10 text-red-400 shadow-[0_0_30px_rgba(239,68,68,0.15)]">
            <ExclamationTriangleIcon className="size-8" aria-hidden="true" />
          </span>
          <span className="eyebrow">ЧТО-ТО ПОШЛО НЕ ТАК</span>
          <h1 className="mt-2 text-2xl font-bold tracking-tight text-white sm:text-3xl">
            Не удалось открыть страницу
          </h1>
          <p className="mx-auto mt-3 max-w-sm text-sm leading-relaxed text-zinc-400">
            Возможно, это временная ошибка. Попробуй ещё раз или вернись на главную.
          </p>
          <div className="mx-auto mt-8 flex w-full max-w-xs flex-col gap-2 sm:flex-row sm:justify-center">
            <Button onClick={reset}>
              <ArrowPathIcon className="size-4" aria-hidden="true" />
              Попробовать снова
            </Button>
            <Link href="/">
              <Button variant="secondary" className="w-full sm:w-auto">
                <HomeIcon className="size-4" aria-hidden="true" />
                На главную
              </Button>
            </Link>
          </div>
          {error.digest && (
            <p className="mt-6 text-xs text-zinc-600">
              Код ошибки: <code className="font-mono">{error.digest}</code>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}