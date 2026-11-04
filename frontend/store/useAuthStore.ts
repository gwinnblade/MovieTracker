// frontend/store/useAuthStore.ts
import { create } from 'zustand';
import { authApi, User } from '@/lib/api/auth';
import toast from 'react-hot-toast';

interface AuthState {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  
  // Действия
  fetchUser: () => Promise<void>;
  login: (data: { login: string; password: string }) => Promise<void>;
  register: (data: any) => Promise<void>;
  logout: () => Promise<void>;
  clearUser: () => void;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  isLoading: false,
  isAuthenticated: false,

  fetchUser: async () => {
    try {
      set({ isLoading: true });
      const user = await authApi.getMe();
      set({ user, isAuthenticated: true });
    } catch (error) {
      set({ user: null, isAuthenticated: false });
    } finally {
      set({ isLoading: false });
    }
  },

  login: async (data) => {
    console.log('Попытка входа:', data);
    try {
      set({ isLoading: true });
      const user = await authApi.login(data);
      console.log('Вход успешен:', user);
      set({ user, isAuthenticated: true });
      toast.success(`Добро пожаловать, ${user.name}!`);
    } catch (error: any) {
      console.error('Ошибка входа:', error);
      const message = error.response?.data?.message || 'Неверный логин или пароль';
      toast.error(message);
      throw error;
    } finally {
      set({ isLoading: false });
    }
  },

  register: async (data) => {
    console.log('Попытка регистрации:', data);
    try {
      set({ isLoading: true });
      const user = await authApi.register(data);
      console.log('Регистрация успешна:', user);
      set({ user, isAuthenticated: true });
      toast.success('Регистрация успешна!');
    } catch (error: any) {
      console.error('Ошибка регистрации:', error);
      const message = error.response?.data?.message || 'Ошибка регистрации';
      const errors = error.response?.data?.errors;
      const firstError = errors ? Object.values(errors)[0][0] : message;
      toast.error(firstError);
      throw error;
    } finally {
      set({ isLoading: false });
    }
  },

  logout: async () => {
    try {
      await authApi.logout();
    } catch (error) {
      console.error('Ошибка при выходе:', error);
    } finally {
      set({ user: null, isAuthenticated: false });
      toast.success('Вы вышли из системы');
    }
  },

  clearUser: () => set({ user: null, isAuthenticated: false }),
}));