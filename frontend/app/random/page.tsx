// frontend/app/random/page.tsx
import { Suspense } from 'react';
import RandomClient from './RandomClient';

export default function RandomPage() {
  return (
    <Suspense fallback={
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12 text-center">
        <p className="text-[var(--text-muted)] text-lg animate-pulse">Загрузка рандомайзера...</p>
      </div>
    }>
      <RandomClient />
    </Suspense>
  );
}