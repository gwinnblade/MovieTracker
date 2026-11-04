// frontend/lib/api/entries.ts
import apiClient from './client';
import { Media } from './media';

export interface Entry {
  id: number;
  media_id: number;
  status_id: number;
  rating: number | null;
  date: string | null;
  note: string | null;
  media?: Media;
  created_at: string;
  updated_at: string;
}

export const STATUS_MAP: Record<number, { name: string; color: 'blue' | 'yellow' | 'green' | 'pink' | 'gray' }> = {
  1: { name: 'Запланировано', color: 'blue' },
  2: { name: 'Смотрю', color: 'yellow' },
  3: { name: 'Просмотрено', color: 'green' },
  4: { name: 'Заброшено', color: 'pink' },
  5: { name: 'Отложено', color: 'gray' },
};

export const entriesApi = {
  getList: async (params?: { status_id?: number }): Promise<Entry[]> => {
    const response = await apiClient.get('/api/v1/entries', { params });
    return Array.isArray(response.data) ? response.data : (response.data.data || []);
  },

  save: async (data: {
    media_id: number;
    status_id: number;
    rating?: number | null;
    date?: string | null;
    note?: string | null;
  }): Promise<Entry> => {
    const response = await apiClient.post('/api/v1/entries', data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await apiClient.delete(`/api/v1/entries/${id}`);
  },
};