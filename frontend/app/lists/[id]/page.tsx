// frontend/app/lists/[id]/page.tsx
'use client';

import { useParams } from 'next/navigation';
import ListClient from './ListClient';

export default function ListPage() {
  const params = useParams();
  const id = Number(params?.id);

  return <ListClient id={id} />;
}