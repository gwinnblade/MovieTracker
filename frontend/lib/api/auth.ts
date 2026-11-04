// frontend/lib/api/auth.ts
import apiClient from './client';

export interface LoginData {
  login: string;
  password: string;
}

export interface RegisterData {
  name: string;
  login: string;
  email: string;
  password: string;
  password_confirmation: string;
}

export interface User {
  id: number;
  name: string;
  login: string;
  email: string;
  role: string | null;
}

export const authApi = {
  // Получение данных текущего пользователя
  getMe: async (): Promise<User> => {
    const response = await apiClient.get('/api/v1/auth/me');
    return response.data;
  },

  // Вход в систему
  login: async (data: LoginData): Promise<User> => {
    const response = await apiClient.post('/api/v1/auth/login', data);
    return response.data;
  },

  // Регистрация
  register: async (data: RegisterData): Promise<User> => {
    const response = await apiClient.post('/api/v1/auth/register', data);
    return response.data;
  },

  // Выход из системы
  logout: async (): Promise<void> => {
    await apiClient.post('/api/v1/auth/logout');
  },
};