// frontend/components/ui/CastSection.tsx
import Link from 'next/link';
import { Media } from '@/lib/api/media';
import {
  VideoCameraIcon,
  UsersIcon,
  BuildingOffice2Icon,
  ArrowUpRightIcon,
} from '@heroicons/react/24/outline';
import { resolveMediaUrl } from '@/lib/utils/media-url';

interface CastSectionProps {
  media: Media;
}

interface Person {
  id: number;
  name: string;
  photo_url?: string | null;
  roles?: Array<{ id: number; name_ru: string; name_en?: string | null }> | null;
}

function isRole(
  role: { name_ru: string; name_en?: string | null },
  kind: 'director' | 'actor'
): boolean {
  const en = (role.name_en ?? '').toLowerCase().trim();
  const ru = (role.name_ru ?? '').toLowerCase().trim();
  if (kind === 'director') {
    return en === 'director' || ru.startsWith('режисс');
  }
  return (
    en === 'actor' ||
    en === 'actress' ||
    ru.startsWith('актер') ||
    ru.startsWith('актрис')
  );
}

function getInitials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

export default function CastSection({ media }: CastSectionProps) {
  const persons: Person[] = media.persons ?? [];
  const companies = media.companies ?? [];

  const directors = persons.filter((p) =>
    p.roles?.some((r) => isRole(r, 'director'))
  );
  const actors = persons.filter((p) =>
    p.roles?.some((r) => isRole(r, 'actor'))
  );

  if (directors.length === 0 && actors.length === 0 && companies.length === 0) {
    return null;
  }

  return (
    <div className="space-y-16">
      {directors.length > 0 && (
        <Section
          id="cast-directors"
          label="Режиссура"
          title={directors.length === 1 ? 'Режиссёр' : 'Режиссёры'}
          count={directors.length}
          icon={<VideoCameraIcon className="w-3 h-3" aria-hidden="true" />}
        >
          <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8">
            {directors.map((d) => (
              <li key={d.id} className="border-b border-[var(--line)]">
                <PersonRow person={d} prominent />
              </li>
            ))}
          </ul>
        </Section>
      )}

      {actors.length > 0 && (
        <Section
          id="cast-actors"
          label="Актёрский состав"
          title="В ролях"
          count={actors.length}
          icon={<UsersIcon className="w-3 h-3" aria-hidden="true" />}
        >
          <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8">
            {actors.map((a) => (
              <li key={a.id} className="border-b border-[var(--line)]">
                <PersonRow person={a} />
              </li>
            ))}
          </ul>
        </Section>
      )}

      {companies.length > 0 && (
        <Section
          id="cast-companies"
          label="Производство"
          title={companies.length === 1 ? 'Студия' : 'Студии'}
          count={companies.length}
          icon={<BuildingOffice2Icon className="w-3 h-3" aria-hidden="true" />}
        >
          <ul className="border-t border-[var(--line)]">
            {companies.map((c, i) => (
              <li
                key={c.id}
                className="flex items-baseline justify-between gap-4 py-3 border-b border-[var(--line)]"
              >
                <span className="font-serif text-lg text-[var(--text-primary)] leading-tight">
                  {c.name}
                </span>
                <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] tabular-nums shrink-0">
                  {String(i + 1).padStart(2, '0')}
                </span>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}

function Section({
  id,
  label,
  title,
  count,
  icon,
  children,
}: {
  id: string;
  label: string;
  title: string;
  count?: number;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section aria-labelledby={id}>
      <div className="flex items-baseline justify-between gap-4 pb-3 mb-6 border-b border-[var(--line)]">
        <div className="flex items-baseline gap-3">
          <span className="text-[var(--text-muted)] inline-flex self-center">{icon}</span>
          <span
            id={id}
            className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]"
          >
            {label}
          </span>
          <span className="text-[var(--text-muted)]/40 hidden sm:inline">·</span>
          <span className="font-serif text-lg sm:text-xl text-[var(--text-primary)] leading-tight hidden sm:inline">
            {title}
          </span>
        </div>
        {count != null && count > 0 && (
          <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] tabular-nums">
            {String(count).padStart(2, '0')}
          </span>
        )}
      </div>
      {children}
    </section>
  );
}

function PersonRow({
  person,
  prominent = false,
}: {
  person: Person;
  prominent?: boolean;
}) {
  const initials = getInitials(person.name);
  const photo = resolveMediaUrl(person.photo_url);

  return (
    <Link
      href={`/persons/${person.id}`}
      className="group flex items-center gap-4 py-4 focus-visible:outline-none"
    >
      <span
        aria-hidden="true"
        className={`shrink-0 overflow-hidden bg-[var(--bg-tertiary)] flex items-center justify-center font-serif text-[var(--text-muted)] transition-colors duration-500 ${
          prominent
            ? 'w-14 h-16 text-base'
            : 'w-12 h-14 text-sm'
        }`}
      >
        {photo ? (
          <img
            src={photo}
            alt=""
            loading="lazy"
            className="w-full h-full object-cover transition-transform duration-[1200ms] ease-[cubic-bezier(0.76,0,0.24,1)] group-hover:scale-[1.06]"
          />
        ) : (
          initials
        )}
      </span>

      <span className="flex-1 min-w-0 flex items-baseline justify-between gap-3">
        <span
          className={`font-serif text-[var(--text-primary)] leading-tight truncate transition-[font-style] duration-300 group-hover:italic ${
            prominent ? 'text-lg' : 'text-base'
          }`}
        >
          {person.name}
        </span>
        <ArrowUpRightIcon
          className="w-3.5 h-3.5 shrink-0 text-[var(--text-muted)] opacity-0 group-hover:opacity-100 transition-opacity duration-500"
          aria-hidden="true"
        />
      </span>
    </Link>
  );
}