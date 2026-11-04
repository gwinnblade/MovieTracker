// frontend/lib/api/profile.ts
import apiClient from './client';

export interface ProfileData {
  user: {
    name: string;
    login: string;
    email: string;
    created_at: string;
  };
  stats: {
    total: number;
    watched: number;
    avg_rating: number;
  };
  top_genres: {
    name_ru: string;
    count: number;
  }[];
  recent_activity: any[];
}

export const profileApi = {
  getProfile: async (): Promise<ProfileData> => {
    const response = await apiClient.get('/api/v1/profile');
    return response.data;
  },
  updateProfile: async (data: any) => {
    const response = await apiClient.put('/api/v1/profile', data);
    return response.data;
  }
};