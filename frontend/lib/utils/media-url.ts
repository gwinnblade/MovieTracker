// frontend/lib/utils/media-url.ts

export function resolveMediaUrl(url?: string | null): string | undefined {
  if (!url) return undefined;

  if (/^https?:\/\//i.test(url)) return url;

  if (url.startsWith('//')) return `https:${url}`;

  if (url.startsWith('/')) {
    return `https://image.tmdb.org/t/p/w500${url}`;
  }

  const base = getBackendOrigin();
  return `${base}/${url}`;
}

function getBackendOrigin(): string {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8080/api';
  try {
    return new URL(apiUrl).origin;
  } catch {
    return 'http://localhost:8080';
  }
}