export interface Reference {
  id: number;
  code: string;
  name_ru: string;
  name_en?: string;
}
export interface User {
  id: number;
  name: string;
  login: string;
  email: string;
  role: string;
  avatar_url?: string | null;
  created_at?: string;
}
export interface Person {
  id?: number;
  tmdb_id?: number;
  name: string;
  photo_url?: string | null;
  character?: string | null;
  roles?: Reference[];
  pivot?: { role_id?: number; character?: string | null };
}
export interface Episode {
  id?: number;
  season: number;
  number: number;
  title: string;
  description_ru?: string;
  duration?: number | null;
  air_date?: string | null;
}
export interface Season {
  season: number;
  name: string;
  episode_count: number;
  poster_url?: string | null;
}
export interface Media {
  id?: number;
  tmdb_id?: number | null;
  tmdb_type?: "movie" | "tv" | null;
  type_id?: number;
  title_ru: string;
  title_en?: string | null;
  original_title?: string | null;
  description_ru?: string | null;
  poster_url?: string | null;
  poster_key?: string | null;
  backdrop_url?: string | null;
  release_date?: string | null;
  type?: Partial<Reference>;
  moderation_status?: string;
  avg_rating?: number | null;
  vote_average?: number;
  runtime?: number | null;
  genres?: { id?: number; name_ru: string }[];
  companies?: { id?: number; name: string }[];
  persons?: Person[];
  cast?: Person[] | null;
  directors?: Person[] | null;
  director?: Person | null;
  episodes?: Episode[];
  seasons?: Season[];
  number_of_episodes?: number | null;
  tmdb_failed_at?: string | null;
}
export interface Page<T> {
  data: T[];
  current_page: number;
  last_page: number;
  per_page: number;
  total: number;
}
export interface EpisodeEntry {
  episode_id: number;
  watched: boolean;
  rating?: number | null;
  note?: string | null;
  episode?: Episode;
}
export interface Entry {
  id: number;
  media_id: number;
  status_id: number;
  status?: Reference;
  rating: number | null;
  date: string | null;
  note: string | null;
  media: Media;
  episodes_watched?: number;
  seasons_watched?: number;
  episode_entries?: EpisodeEntry[];
  created_at: string;
  updated_at: string;
}
export interface SeasonProgress {
  season: number;
  watched: number;
  status: string;
}
export interface EpisodeNote {
  id: number;
  season: number;
  episode: number;
  note: string;
}
export interface Tracking {
  entry: Entry | null;
  seasons: SeasonProgress[];
  episode_notes: EpisodeNote[];
}
export interface Collection {
  id: number;
  user_id?: number;
  name: string;
  description?: string | null;
  cover_url?: string | null;
  is_public: boolean;
  share_token: string | null;
  media_count: number;
  media?: Media[];
  created_at: string;
}
export interface ModerationRequest {
  id: number;
  title_ru: string;
  title_en?: string | null;
  type_id: number;
  type?: Reference;
  release_year?: string | null;
  description_ru?: string | null;
  poster_key?: string | null;
  status: "pending" | "approved" | "rejected";
  action: "create" | "edit";
  rejection_reason?: string | null;
  media_id?: number | null;
  tmdb_id?: number | null;
  tmdb_type?: string | null;
  user?: { name: string; login: string };
  genres?: { id: number; name_ru: string }[];
  created_at: string;
}
export interface Profile {
  user: User;
  stats: {
    total: number;
    watched: number;
    movies: number;
    series: number;
    rated: number;
    avg_rating: number;
    episodes_watched: number;
    collections: number;
    statuses: { name: string; count: number }[];
  };
  top_genres: { name_ru: string; count: number }[];
  recent_activity: Entry[];
  continue_watching: Entry[];
  top_rated: Entry[];
}
