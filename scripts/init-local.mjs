import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
async function initialize(name, secrets = false) {
  const path = resolve(root, name, '.env');
  let content;
  try { content = await readFile(path, 'utf8'); }
  catch { content = await readFile(resolve(root, name, '.env.example'), 'utf8'); }
  if (secrets) {
    if (/^APP_KEY=\s*$/m.test(content)) content = content.replace(/^APP_KEY=\s*$/m, 'APP_KEY=base64:' + randomBytes(32).toString('base64'));
    if (/^LOCAL_ADMIN_PASSWORD=\s*$/m.test(content)) content = content.replace(/^LOCAL_ADMIN_PASSWORD=\s*$/m, 'LOCAL_ADMIN_PASSWORD=' + randomBytes(18).toString('base64url'));
  }
  await writeFile(path, content, { mode: 0o600 });
}
await initialize('backend', true);
await initialize('frontend');
await mkdir(resolve(root, 'backend/storage'), { recursive: true });
process.stdout.write('Локальные .env подготовлены. Пароль администратора хранится в backend/.env.\n');
