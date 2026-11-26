"use client";

import { ArrowLeftIcon, MagnifyingGlassIcon } from "@heroicons/react/24/outline";
import Link from "next/link";
import { Button } from "@/components/UI";

export default function NotFound() {
  return (
    <div className="mx-auto mt-20 max-w-xl px-4">
      <div className="relative overflow-hidden rounded-3xl border border-white/5 bg-gradient-to-br from-[#151921] to-[#0B0E14] p-8 text-center shadow-[0_30px_80px_rgba(0,0,0,0.5)] sm:p-10">
        <div
          className="pointer-events-none absolute -top-32 left-1/2 size-64 -translate-x-1/2 rounded-full bg-gold/10 blur-3xl"
          aria-hidden="true"
        />
        <div className="relative">
          <p className="text-7xl font-bold tracking-tighter text-gold/90 sm:text-8xl">
            404
          </p>
          <span className="eyebrow mt-4">СТРАНИЦА НЕ НАЙДЕНА</span>
          <h1 className="mt-2 text-2xl font-bold tracking-tight text-white sm:text-3xl">
            Похоже, эта история потерялась
          </h1>
          <p className="mx-auto mt-3 max-w-sm text-sm leading-relaxed text-zinc-400">
            Возможно, страница была удалена или ты ошибся в адресе. Давай вернёмся к кино.
          </p>
          <div className="mx-auto mt-8 flex w-full max-w-sm flex-col gap-2 sm:flex-row sm:justify-center">
            <Link href="/">
              <Button className="w-full sm:w-auto">
                <ArrowLeftIcon className="size-4" aria-hidden="true" />
                На главную
              </Button>
            </Link>
            <Link href="/catalog">
              <Button variant="secondary" className="w-full sm:w-auto">
                <MagnifyingGlassIcon className="size-4" aria-hidden="true" />
                В каталог
              </Button>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}