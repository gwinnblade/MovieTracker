"use client";

import { useState, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "react-hot-toast";
import { AuthProvider } from "@/components/Auth";

export default function Providers({ children }: { children: ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 60000,
            refetchOnWindowFocus: false,
            retry: false,
          },
        },
      }),
  );
  return (
    <QueryClientProvider client={client}>
      <AuthProvider>{children}</AuthProvider>
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: "#1a1d24",
            color: "#f4f3ee",
            border: "1px solid rgba(255, 255, 255, 0.09)",
            borderRadius: "10px",
            boxShadow: "0 16px 48px rgba(0, 0, 0, 0.4)",
          },
          duration: 4500,
        }}
      />
    </QueryClientProvider>
  );
}
