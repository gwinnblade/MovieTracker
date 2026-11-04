// frontend/app/public/lists/[token]/page.tsx
'use client';

import { useParams } from 'next/navigation';
import PublicListClient from './PublicListClient';

export default function PublicListPage() {
  const params = useParams();
  const token = String(params?.token || '');

  return <PublicListClient token={token} />;
}