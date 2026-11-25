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
            background: "#20232a",
            color: "#f2f3f5",
            border: "1px solid #363b46",
          },
          duration: 4500,
        }}
      />
    </QueryClientProvider>
  );
}
