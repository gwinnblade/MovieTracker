// frontend/lib/api/media.ts
import apiClient from './client';

export interface Episode {
  id: number;
  number: number;
  season: number;
  title_ru: string | null;
  description_ru: string | null;
  duration: number | null;
}

export interface Person {
  id: number;
  name: string;
  photo_key: string | null;
  pivot: {
    role_id: number;
  };
}

export interface Company {
  id: number;
  name: string;
  logo_key: string | null;
  pivot: {
    role_id: number;
  };
}

export interface Person {
  id: number;
  name: string;
  photo_url?: string;
  filmography: Array<{
    id: number;
    title_ru: string;
    title_en?: string;
    poster_url?: string;
    release_date?: string;
    year?: number;
    type?: { code: string; name_ru: string };
    pivot: {
      character?: string;
      role_name_ru: string;
    };
  }>;
}

export interface SimilarMoviesResponse {
  director: { id: number; name: string } | null;
  movies: Array<{
    id: number;
    title_ru: string;
    title_en?: string;
    poster_url?: string;
    release_date?: string;
    year?: number;
    type?: { code: string; name_ru: string };
  }>;
}

export interface Media {
  id: number;
  title_ru: string;
  title_en: string | null;
  description_ru: string | null;
  type_id: number;
  type?: {
    id: number;
    code: string;
    name_ru: string;
    name_en: string;
  };
  genres?: Array<{
    id: number;
    name_ru: string;
    name_en: string;
  }>;
  companies?: Array<{
    id: number;
    name: string;
  }>;
  persons?: Array<{
    id: number;
    name: string;
    photo_url?: string;
    roles?: Array<{ id: number; name_ru: string; name_en: string }>;
    pivot?: {
      role_id: number;
      character?: string;
    };
  }>;
  episodes?: Episode[];
  release_date: string | null;
  moderation_status: string;
  created_at: string;
  updated_at: string;
  poster_url?: string; 
  poster_key?: string;
}

export interface MediaListResponse {
  data: Media[];
  current_page: number;
  last_page: number;
  per_page: number;
  total: number;
}

export const personApi = {
  getById: async (id: number): Promise<Person> => {
    const response = await apiClient.get(`/api/v1/persons/${id}`);
    return response.data;
  },
};

export const mediaApi = {
  getList: async (params: {
    search?: string;
    type_id?: number;
    genre_id?: number;
    sort_by?: string;
    sort_direction?: 'asc' | 'desc';
    per_page?: number;
    page?: number;
  }): Promise<MediaListResponse> => {
    const response = await apiClient.get('/api/v1/media', { params });
    return response.data;
  },

  getById: async (id: number): Promise<Media> => {
    const response = await apiClient.get(`/api/v1/media/${id}`);
    return response.data;
  },


  getRandom: async (): Promise<Media> => {
    const response = await apiClient.get('/api/v1/media/random');
    return response.data;
  },
  getSimilar: async (id: number): Promise<SimilarMoviesResponse> => {
    const response = await apiClient.get(`/api/v1/media/${id}/similar`);
    return response.data;
  },
};