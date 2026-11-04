// frontend/lib/api/reference.ts
import apiClient from './client';

// ========== Интерфейсы ==========

export interface Type {
  id: number;
  code: string;
  name_ru: string;
  name_en: string;
}

export interface Genre {
  id: number;
  name_ru: string;
  name_en: string;
}

export interface Status {
  id: number;
  code: string;
  name_ru: string;
  name_en: string;
  color: string;
}

export interface Role {
  id: number;
  name: string;
  description: string;
}

// ========== API методы ==========

export const referenceApi = {
  // Получить все типы медиа (Фильмы, Сериалы, Аниме, Мультфильмы)
  getTypes: async (): Promise<Type[]> => {
    const response = await apiClient.get('/api/v1/reference/types');
    return response.data;
  },

  // Получить все жанры
  getGenres: async (): Promise<Genre[]> => {
    const response = await apiClient.get('/api/v1/reference/genres');
    return response.data;
  },

  // Получить все статусы отметок (Просмотрено, В процессе, Запланировано и т.д.)
  getStatuses: async (): Promise<Status[]> => {
    const response = await apiClient.get('/api/v1/reference/statuses');
    return response.data;
  },

  // Получить все роли пользователей
  getRoles: async (): Promise<Role[]> => {
    const response = await apiClient.get('/api/v1/reference/roles');
    return response.data;
  },
};