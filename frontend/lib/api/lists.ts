// frontend/lib/api/lists.ts
import apiClient from './client';
import { Media } from './media';

export interface UserList {
  id: number;
  user_id: number;
  name: string;
  is_public: boolean;
  share_token: string | null;
  media_count: number;
  media?: Media[];
  created_at: string;
  updated_at: string;
}

export const listsApi = {
  getList: async (): Promise<UserList[]> => {
    const response = await apiClient.get('/api/v1/lists');
    return Array.isArray(response.data) ? response.data : (response.data.data || []);
  },

  // Создать новый список
  create: async (data: { name: string; is_public: boolean }): Promise<UserList> => {
    const response = await apiClient.post('/api/v1/lists', data);
    return response.data;
  },

  // Получить детализацию конкретного списка (с медиа внутри)
  getById: async (id: number): Promise<UserList> => {
    const response = await apiClient.get(`/api/v1/lists/${id}`);
    return response.data;
  },

  // Добавить медиа в список
  addMedia: async (listId: number, mediaId: number): Promise<void> => {
    await apiClient.post(`/api/v1/lists/${listId}/media`, { media_id: mediaId });
  },

  // Удалить медиа из списка
  removeMedia: async (listId: number, mediaId: number): Promise<void> => {
    await apiClient.delete(`/api/v1/lists/${listId}/media/${mediaId}`);
  },

  // Удалить весь список
  delete: async (id: number): Promise<void> => {
    await apiClient.delete(`/api/v1/lists/${id}`);
  },
};

// API для публичных списков (без авторизации)
export const publicListsApi = {
  getByToken: async (token: string): Promise<UserList> => {
    const response = await apiClient.get(`/api/v1/public/lists/${token}`);
    return response.data.data || response.data;
  }
};