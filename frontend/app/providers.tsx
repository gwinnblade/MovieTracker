// frontend/app/providers.tsx
'use client';

import { useState, type ReactNode } from 'react';
import { Suspense } from 'react';
import {
  QueryClient,
  QueryClientProvider,
  QueryCache,
  MutationCache,
} from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { Toaster, ToastBar, toast } from 'react-hot-toast';

function makeQueryClient() {
  return new QueryClient({
    queryCache: new QueryCache({
      onError: (error: any, query) => {
        if (query.meta?.skipGlobalError) return;

        const status = error?.response?.status;
        if (status === 401) {
          return;
        }
        if (status && status >= 500) {
          toast.error('Сервер недоступен. Попробуйте позже');
        }
      },
    }),
    mutationCache: new MutationCache({
      onError: (error: any, _vars, _ctx, mutation) => {
        if (mutation.meta?.skipGlobalError) return;
        const status = error?.response?.status;
        if (status && status >= 500) {
          toast.error('Не удалось сохранить изменения');
        }
      },
    }),
    defaultOptions: {
      queries: {
        staleTime: 60 * 1000, // 1 минута для обычных запросов
        gcTime: 5 * 60 * 1000, // 5 минут в кэше
        refetchOnWindowFocus: false,
        refetchOnReconnect: true,
        retry: (failureCount, error: any) => {
          const status = error?.response?.status;
          if (status && status >= 400 && status < 500) return false;
          return failureCount < 2;
        },
      },
      mutations: {
        retry: 0,
      },
    },
  });
}

let browserQueryClient: QueryClient | undefined;
function getQueryClient() {
  if (typeof window === 'undefined') return makeQueryClient();
  if (!browserQueryClient) browserQueryClient = makeQueryClient();
  return browserQueryClient;
}

export default function Providers({ children }: { children: ReactNode }) {
  const [queryClient] = useState(() => getQueryClient());

  return (
    <QueryClientProvider client={queryClient}>
      {children}

      <Toaster
        position="top-right"
        gutter={12}
        reverseOrder={false}
        containerStyle={{
          top: 80,
          right: 20,
          left: 20,
          maxWidth: 400,
          marginLeft: 'auto',
        }}
        toastOptions={{
          duration: 3500,
          style: {
            background: 'var(--bg-primary)',
            color: 'var(--text-primary)',
            border: '1px solid var(--line)',
            borderRadius: 0,
            boxShadow: 'none',
            padding: '14px 16px',
            fontSize: 13,
            fontWeight: 400,
            maxWidth: 400,
            lineHeight: 1.5,
            letterSpacing: '0.005em',
          },
          success: {
            duration: 3000,
            style: {
              borderLeft: '2px solid var(--accent-green)',
            },
            iconTheme: {
              primary: 'var(--accent-green)',
              secondary: 'var(--bg-primary)',
            },
          },
          error: {
            duration: 6000,
            style: {
              borderLeft: '2px solid var(--accent-red)',
            },
            iconTheme: {
              primary: 'var(--accent-red)',
              secondary: 'var(--bg-primary)',
            },
          },
          loading: {
            duration: Infinity,
            style: {
              borderLeft: '2px solid var(--text-muted)',
            },
            iconTheme: {
              primary: 'var(--text-muted)',
              secondary: 'var(--bg-primary)',
            },
          },
        }}
      >
        {(t) => (
          <ToastBar toast={t}>
            {({ icon, message }) => (
              <div className="flex items-start gap-3 w-full">
                <span className="shrink-0 mt-0.5">{icon}</span>
                <div className="flex-1 min-w-0 text-[var(--text-primary)]">
                  {message}
                </div>
                {t.type !== 'loading' && (
                  <button
                    type="button"
                    onClick={() => toast.dismiss(t.id)}
                    aria-label="Закрыть уведомление"
                    className="shrink-0 -mr-1 -mt-1 p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                  >
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.5"
                      className="w-3.5 h-3.5"
                      aria-hidden="true"
                    >
                      <path d="M18 6L6 18M6 6l12 12" />
                    </svg>
                  </button>
                )}
              </div>
            )}
          </ToastBar>
        )}
      </Toaster>

      {process.env.NODE_ENV === 'development' && (
        <ReactQueryDevtools
          initialIsOpen={false}
          buttonPosition="bottom-left"
        />
      )}
    </QueryClientProvider>
  );
}