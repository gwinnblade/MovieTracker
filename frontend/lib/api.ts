import axios from "axios";
import Cookies from "js-cookie";
import type {
  Collection,
  Entry,
  Media,
  ModerationRequest,
  Page,
  Person,
  Profile,
  Reference,
  Tracking,
  User,
  Episode,
  EpisodeEntry,
} from "./types";

export function backendOrigin(): string {
  const url = new URL(
    process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081",
  );
  if (
    typeof window !== "undefined" &&
    ["localhost", "127.0.0.1"].includes(window.location.hostname) &&
    ["localhost", "127.0.0.1"].includes(url.hostname)
  ) {
    url.hostname = window.location.hostname;
  }
  return url.origin;
}

export function imageUrl(path?: string | null): string | undefined {
  if (!path) return undefined;
  if (/^(?:https?:)?\/\/image\.tmdb\.org\/t\/p\//i.test(path)) {
    return (
      backendOrigin() +
      "/tmdb-images/" +
      path.replace(/^(?:https?:)?\/\/image\.tmdb\.org\/t\/p\//i, "")
    );
  }
  if (/^https?:\/\//i.test(path)) return path;
  if (path.startsWith("/tmdb-images/") || path.startsWith("/storage/"))
    return backendOrigin() + path;
  if (path.startsWith("/")) return backendOrigin() + "/tmdb-images/w500" + path;
  return backendOrigin() + "/" + path;
}

const client = axios.create({
  baseURL: backendOrigin(),
  withCredentials: true,
  headers: { Accept: "application/json" },
});
let csrfRequest: Promise<unknown> | null = null;
async function csrf() {
  csrfRequest ??= axios
    .get(backendOrigin() + "/sanctum/csrf-cookie", { withCredentials: true })
    .finally(() => {
      csrfRequest = null;
    });
  await csrfRequest;
  return Cookies.get("XSRF-TOKEN");
}
client.interceptors.request.use(async (config) => {
  if (["post", "put", "patch", "delete"].includes(config.method || "")) {
    const token = await csrf();
    if (token) config.headers.set("X-XSRF-TOKEN", token);
  }
  if (config.data instanceof FormData) config.headers.delete("Content-Type");
  return config;
});

export function errorMessage(error: unknown): string {
  if (
    axios.isAxiosError<{ message?: string; errors?: Record<string, string[]> }>(
      error,
    )
  ) {
    if (error.response?.status === 401)
      return "Войдите в аккаунт, чтобы продолжить.";
    if (error.response?.status === 419)
      return "Сессия истекла. Обновите страницу и попробуйте снова.";
    if (error.response?.status === 429)
      return "Слишком много запросов. Попробуйте через минуту.";
    const messages = error.response?.data.errors;
    return (
      (messages && Object.values(messages)[0]?.[0]) ||
      error.response?.data.message ||
      "Не удалось связаться с сервером."
    );
  }
  return error instanceof Error
    ? error.message
    : "Не удалось выполнить действие.";
}

type Params = Record<string, string | number | boolean | undefined>;
const get = async <T>(path: string, params?: Params): Promise<T> =>
  (await client.get<T>("/api/v1/" + path, { params })).data;
const post = async <T>(path: string, body?: unknown): Promise<T> =>
  (await client.post<T>("/api/v1/" + path, body)).data;
const put = async <T>(path: string, body: unknown): Promise<T> =>
  (await client.put<T>("/api/v1/" + path, body)).data;
const remove = async (path: string): Promise<void> => {
  await client.delete("/api/v1/" + path);
};

export const api = {
  me: () => get<User>("auth/me"),
  login: (body: { login: string; password: string; remember: boolean }) =>
    post<User>("auth/login", body),
  register: (body: {
    login: string;
    name: string;
    email: string;
    password: string;
    password_confirmation: string;
  }) => post<User>("auth/register", body),
  logout: () => post<void>("auth/logout"),
  forgot: (email: string) =>
    post<{ message: string }>("auth/forgot-password", { email }),
  reset: (body: {
    email: string;
    token: string;
    password: string;
    password_confirmation: string;
  }) => post<{ message: string }>("auth/reset-password", body),
  references: (name: string) => get<Reference[]>("reference/" + name),
  trending: (params?: Params) => get<Page<Media>>("tmdb/trending", params),
  search: (params: Params) => get<Page<Media>>("tmdb/search", params),
  tmdbDetails: (type: string, id: number) =>
    get<Media>("tmdb/details", { type, tmdb_id: id }),
  tmdbSeason: (id: number, season: number) =>
    get<{ name: string; season: number; episodes: Episode[] }>(
      `tmdb/tv/${id}/season/${season}`,
    ),
  saveTmdb: (type: string, id: number) =>
    post<Media>("tmdb/save", { tmdb_type: type, tmdb_id: id }),
  catalog: (params?: Params) => get<Page<Media>>("media", params),
  media: (id: number) => get<Media>("media/" + id),
  similar: (id: number) =>
    get<{ director: Person | null; movies: Media[] }>(`media/${id}/similar`),
  random: (params?: Params) => get<Media>("media/random", params),
  person: (id: number) =>
    get<
      Person & {
        filmography: (Media & {
          pivot: { character?: string; role_name_ru: string };
        })[];
      }
    >("persons/" + id),
  tracking: (id: number) => get<Tracking>(`media/${id}/tracking`),
  season: (id: number, season: number) =>
    get<{ name: string; season: number; episodes: Episode[] }>(
      `media/${id}/seasons/${season}`,
    ),
  progress: (id: number, season: number, watched: number, status?: string) =>
    put(`media/${id}/seasons/${season}/progress`, { watched, status }),
  episodeNote: (id: number, season: number, episode: number, note: string) =>
    put(`media/${id}/seasons/${season}/episodes/${episode}/note`, { note }),
  entries: (params?: Params) => get<Page<Entry>>("entries", params),
  saveEntry: (body: {
    media_id: number;
    status_id: number;
    rating?: number | null;
    note?: string | null;
    date?: string | null;
    episodes?: EpisodeEntry[];
  }) => post<Entry>("entries", body),
  deleteEntry: (id: number) => remove("entries/" + id),
  profile: () => get<Profile>("profile"),
  updateProfile: (body: FormData) =>
    post<{ user: User; message: string }>("profile", body),
  summary: () =>
    get<{ catalog: number; users: number; entries: number }>("summary"),
  recommendations: () => get<Page<Media>>("recommendations"),
  collections: () => get<Collection[]>("lists"),
  collection: (id: number) => get<Collection>("lists/" + id),
  publicCollection: async (token: string) =>
    (await get<{ data: Collection }>("public/lists/" + token)).data,
  collectionById: async (id: number) =>
    (await get<{ data: Collection }>("public/collections/" + id)).data,
  createCollection: (body: FormData) => post<Collection>("lists", body),
  updateCollection: (id: number, body: FormData) =>
    post<Collection>("lists/" + id, body),
  deleteCollection: (id: number) => remove("lists/" + id),
  addToCollection: (list: number, media: number) =>
    post(`lists/${list}/media`, { media_id: media }),
  removeFromCollection: (list: number, media: number) =>
    remove(`lists/${list}/media/${media}`),
  requests: (status?: string) =>
    get<ModerationRequest[]>(
      "moderation/requests",
      status ? { status } : undefined,
    ),
  suggest: (body: FormData) =>
    post<ModerationRequest>("moderation/requests", body),
  approve: (id: number) =>
    post<{ media_id: number }>(`moderation/requests/${id}/approve`),
  reject: (id: number, reason: string) =>
    post(`moderation/requests/${id}/reject`, { reason }),
};

export function mediaHref(media: Media): string {
  if (media.id && media.moderation_status === "approved")
    return "/media/" + media.id;
  if (media.tmdb_id && media.tmdb_type)
    return `/title/${media.tmdb_type}/${media.tmdb_id}`;
  return "/media/" + media.id;
}
export function safeNext(value: string | null): string {
  return value &&
    value.startsWith("/") &&
    !value.startsWith("//") &&
    !value.includes("\\")
    ? value
    : "/profile";
}
