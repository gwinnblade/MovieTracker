import { useQuery } from '@tanstack/react-query';
import { referenceApi } from '@/lib/api/reference';


export const referenceKeys = {
  all: ['references'] as const,
  types: ['references', 'types'] as const,
  genres: ['references', 'genres'] as const,
};

export function useMediaTypes() {
  return useQuery({
    queryKey: referenceKeys.types,
    queryFn: () => referenceApi.getTypes(),
    staleTime: 1000 * 60 * 60 * 24,
    gcTime: 1000 * 60 * 60 * 24 * 7,
    refetchOnWindowFocus: false,
    refetchOnMount: false,
  });
}

export function useGenres() {
  return useQuery({
    queryKey: referenceKeys.genres,
    queryFn: () => referenceApi.getGenres(),
    staleTime: 1000 * 60 * 60 * 24,
    gcTime: 1000 * 60 * 60 * 24 * 7,
    refetchOnWindowFocus: false,
    refetchOnMount: false,
  });
}

export function useAllReferences() {
  return useQuery({
    queryKey: referenceKeys.all,
    queryFn: async () => {
      const [types, genres] = await Promise.all([
        referenceApi.getTypes(),
        referenceApi.getGenres(),
      ]);
      return { types, genres };
    },
    staleTime: 1000 * 60 * 60 * 24,
    gcTime: 1000 * 60 * 60 * 24 * 7,
    refetchOnWindowFocus: false,
    refetchOnMount: false,
  });
}