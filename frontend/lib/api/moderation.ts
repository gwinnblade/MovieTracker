// frontend/lib/api/moderation.ts
import apiClient from './client';

export interface ModerationRequest {
  id: number;
  user_id: number;
  title_ru: string;
  title_en: string | null;
  type_id: number;
  type?: { id: number; name_ru: string };
  release_year: string | null;
  description_ru: string | null;
  status: 'pending' | 'approved' | 'rejected';
  rejection_reason: string | null;
  user?: { name: string; login: string };
  created_at: string;
}

export const moderationApi = {
  // Получить все заявки
  getRequests: async (): Promise<ModerationRequest[]> => {
    const response = await apiClient.get('/api/v1/moderation/requests');
    return Array.isArray(response.data) ? response.data : (response.data.data || []);
  },

  // Отправить новую заявку
  submit: async (data: FormData) => {
    const response = await apiClient.post('/api/v1/moderation/requests', data, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  // Одобрить
  approve: async (id: number): Promise<any> => {
    const response = await apiClient.post(`/api/v1/moderation/requests/${id}/approve`);
    return response.data;
  },

  // Отклонить
  reject: async (id: number, reason: string): Promise<any> => {
    const response = await apiClient.post(`/api/v1/moderation/requests/${id}/reject`, { reason });
    return response.data;
  },
};