// frontend/app/media/[id]/page.tsx
'use client';
import CastSection from '@/components/ui/CastSection';
import { useParams } from 'next/navigation';
import MediaClient from './MediaClient';

export default function MediaPage() {
  const params = useParams();
  const id = Number(params?.id);

  return <MediaClient id={id} />;
}