import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

// The local VPN's system DNS returns loopback for TMDB. Resolve it over HTTPS
// for Docker only; do not change the computer's DNS or /etc/hosts.
const names = ['api.themoviedb.org', 'image.tmdb.org'];
const answers = await Promise.all(names.map(async (name) => {
  for (const base of ['https://dns.google/resolve', 'https://cloudflare-dns.com/dns-query']) {
    try {
      const response = await fetch(`${base}?name=${name}&type=A`, {
        headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(10000),
      });
      if (!response.ok) continue;
      const body = await response.json();
      const ip = body.Answer?.find((a) => a.type === 1 && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(a.data) && !a.data.startsWith('127.') && a.data !== '0.0.0.0')?.data;
      if (ip) return { name, ip };
    } catch { /* try the next HTTPS resolver */ }
  }
  throw new Error(`Не удалось определить адрес ${name}. Проверьте соединение и VPN.`);
}));
await writeFile(resolve(import.meta.dirname, '../docker-compose.override.yml'),
  'services:\n  backend:\n    extra_hosts:\n' + answers.map(({ name, ip }) => `      - "${name}:${ip}"\n`).join(''));
process.stdout.write('Адреса TMDB для Docker обновлены.\n');
