// frontend/lib/api/tmdb.ts
import apiClient from './client';

export interface TmdbMovie {
  tmdb_id: number;
  title_ru: string;
  title_en?: string;
  release_date?: string;
  overview?: string;
  poster_url?: string;
  vote_average?: number;
}

export interface TmdbDetails {
  cast: { tmdb_id: number; name: string; character: string }[];
  director: { tmdb_id: number; name: string } | null;
  companies: { name: string }[];
}

export const tmdbApi = {
  search: async (query: string): Promise<TmdbMovie[]> => {
    const response = await apiClient.get('/api/v1/tmdb/search', {
      params: { query },
    });
    return response.data;
  },

  getDetails: async (tmdbId: number): Promise<TmdbDetails> => {
    const response = await apiClient.get('/api/v1/tmdb/details', {
      params: { tmdb_id: tmdbId },
    });
    return response.data;
  },
};