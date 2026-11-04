// frontend/lib/queryClient.ts
import { QueryClient } from '@tanstack/react-query';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // Данные считаются "свежими" 5 минут
      retry: 1, // Повторять запрос при ошибке только 1 раз
      refetchOnWindowFocus: false, // Не обновлять данные при каждом возврате на вкладку
    },
  },
});