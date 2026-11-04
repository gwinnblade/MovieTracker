// frontend/components/ui/CreditsList.tsx
'use client';

import Link from 'next/link';
import Image from 'next/image';
import { useMemo, useState } from 'react';
import { resolveMediaUrl } from '@/lib/utils/media-url';
import {
  VideoCameraIcon,
  UsersIcon,
  BuildingOffice2Icon,
  PencilIcon,
  MusicalNoteIcon,
  ArrowRightIcon,
  ArrowUpRightIcon,
} from '@heroicons/react/24/outline';

interface Role {
  id: number;
  name_ru: string;
  name_en?: string | null;
}

interface Person {
  id: number;
  name: string;
  photo_url?: string | null;
  roles?: Role[] | null;
  pivot?: {
    character?: string | null;
    role_id?: number;
  };
}

interface Company {
  id: number;
  name: string;
  logo_url?: string | null;
}

interface CreditsListProps {
  persons?: Person[] | null;
  companies?: Company[] | null;
}

const ACTORS_LIMIT = 12;

type RoleKind = 'director' | 'actor' | 'writer' | 'composer' | 'other';

function normalizeRole(role: Role): RoleKind {
  const en = (role.name_en ?? '').toLowerCase().trim();
  const ru = (role.name_ru ?? '').toLowerCase().trim();
  if (en === 'director' || ru.startsWith('режисс')) return 'director';
  if (en === 'actor' || en === 'actress' || ru.startsWith('актер') || ru.startsWith('актрис')) {
    return 'actor';
  }
  if (en === 'writer' || en === 'screenplay' || ru.startsWith('сценар')) return 'writer';
  if (en === 'composer' || ru.startsWith('композит')) return 'composer';
  return 'other';
}

function getInitials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}



export default function CreditsList({
  persons: personsRaw = [],
  companies: companiesRaw = [],
}: CreditsListProps) {
  const persons = personsRaw ?? [];
  const companies = companiesRaw ?? [];
  const [showAllActors, setShowAllActors] = useState(false);

  const { directors, actors, writers, composers } = useMemo(() => {
    const d: Person[] = [];
    const a: Person[] = [];
    const w: Person[] = [];
    const c: Person[] = [];

    for (const person of persons) {
      if (!person.roles?.length) continue;
      const kinds = new Set(person.roles.map(normalizeRole));
      if (kinds.has('director')) d.push(person);
      if (kinds.has('actor')) a.push(person);
      if (kinds.has('writer')) w.push(person);
      if (kinds.has('composer')) c.push(person);
    }
    return { directors: d, actors: a, writers: w, composers: c };
  }, [persons]);

  if (
    directors.length === 0 &&
    actors.length === 0 &&
    writers.length === 0 &&
    composers.length === 0 &&
    companies.length === 0
  ) {
    return null;
  }

  const visibleActors = showAllActors ? actors : actors.slice(0, ACTORS_LIMIT);
  const hiddenActorsCount = actors.length - visibleActors.length;

  return (
    <div className="space-y-20">
      {directors.length > 0 && (
        <Group
          label="Режиссура"
          title={directors.length === 1 ? 'Режиссёр' : 'Режиссёры'}
          count={directors.length}
          icon={<VideoCameraIcon className="w-3 h-3" aria-hidden="true" />}
        >
          <PeopleGrid people={directors} prominent />
        </Group>
      )}

      {actors.length > 0 && (
        <Group
          label="Актёрский состав"
          title="В ролях"
          count={actors.length}
          icon={<UsersIcon className="w-3 h-3" aria-hidden="true" />}
        >
          <PeopleGrid people={visibleActors} showCharacter />

          {hiddenActorsCount > 0 && !showAllActors && (
            <div className="mt-8">
              <button
                type="button"
                onClick={() => setShowAllActors(true)}
                className="group inline-flex items-center gap-3"
              >
                <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] border-b border-transparent group-hover:border-[var(--text-primary)] pb-0.5 transition-colors">
                  Показать ещё {hiddenActorsCount}
                </span>
                <span className="w-8 h-8 rounded-full border border-[var(--line)] grid place-items-center group-hover:border-[var(--text-primary)] transition-colors">
                  <ArrowRightIcon className="w-3 h-3" />
                </span>
              </button>
            </div>
          )}
        </Group>
      )}

      {writers.length > 0 && (
        <Group
          label="Сценарий"
          title={writers.length === 1 ? 'Сценарий' : 'Сценаристы'}
          count={writers.length}
          icon={<PencilIcon className="w-3 h-3" aria-hidden="true" />}
        >
          <PeopleGrid people={writers} />
        </Group>
      )}

      {composers.length > 0 && (
        <Group
          label="Музыка"
          title={composers.length === 1 ? 'Композитор' : 'Композиторы'}
          count={composers.length}
          icon={<MusicalNoteIcon className="w-3 h-3" aria-hidden="true" />}
        >
          <PeopleGrid people={composers} />
        </Group>
      )}

      {companies.length > 0 && (
        <Group
          label="Производство"
          title={companies.length === 1 ? 'Студия' : 'Студии'}
          count={companies.length}
          icon={<BuildingOffice2Icon className="w-3 h-3" aria-hidden="true" />}
        >
          <ul className="border-t border-[var(--line)]">
            {companies.map((c, i) => {
              const logo = resolveMediaUrl(c.logo_url);
              return (
                <li
                  key={c.id}
                  className="flex items-center gap-4 py-3.5 border-b border-[var(--line)]"
                >
                  <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] tabular-nums min-w-[24px]">
                    {String(i + 1).padStart(2, '0')}
                  </span>

                  {logo && (
                    <span className="shrink-0 w-8 h-8 grid place-items-center bg-[var(--bg-tertiary)]">
                      <img
                        src={logo}
                        alt=""
                        loading="lazy"
                        className="w-6 h-6 object-contain"
                      />
                    </span>
                  )}

                  <span className="flex-1 font-serif text-base text-[var(--text-primary)] truncate">
                    {c.name}
                  </span>
                </li>
              );
            })}
          </ul>
        </Group>
      )}
    </div>
  );
}

function Group({
  label,
  title,
  count,
  icon,
  children,
}: {
  label: string;
  title: string;
  count?: number;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section aria-labelledby={`credits-${label}`}>
      {/* Заголовок группы — редакционная полоса */}
      <div className="grid lg:grid-cols-12 gap-4 lg:gap-8 pb-4 mb-8 border-b border-[var(--line)] items-baseline">
        <div className="lg:col-span-4 flex items-baseline gap-3">
          <span className="text-[var(--text-muted)] inline-flex self-center">
            {icon}
          </span>
          <span
            id={`credits-${label}`}
            className="font-mono text-[10px] uppercase tracking-[0.25em] text-[var(--text-muted)]"
          >
            {label}
          </span>
        </div>

        <div className="lg:col-span-7">
          <p className="font-serif text-2xl sm:text-3xl leading-none tracking-[-0.02em] text-[var(--text-primary)]">
            {title}
          </p>
        </div>

        <div className="lg:col-span-1 lg:text-right">
          {count != null && count > 0 && (
            <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] tabular-nums">
              {String(count).padStart(2, '0')}
            </span>
          )}
        </div>
      </div>

      {children}
    </section>
  );
}

function PeopleGrid({
  people,
  prominent = false,
  showCharacter = false,
}: {
  people: Person[];
  prominent?: boolean;
  showCharacter?: boolean;
}) {
  return (
    <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 lg:gap-x-10">
      {people.map((person, i) => (
        <li key={person.id} className="border-b border-[var(--line)]">
          <PersonRow
            person={person}
            index={i}
            prominent={prominent}
            showCharacter={showCharacter}
          />
        </li>
      ))}
    </ul>
  );
}

function PersonRow({
  person,
  index,
  prominent = false,
  showCharacter = false,
}: {
  person: Person;
  index: number;
  prominent?: boolean;
  showCharacter?: boolean;
}) {
  const initials = getInitials(person.name);
  const photo = resolveMediaUrl(person.photo_url);
  const character = showCharacter ? person.pivot?.character?.trim() : undefined;

  if (person.name.includes('Ховард') || person.name.includes('Хемсворт') || person.name.includes('Питт')) {
    console.log('DEBUG PERSON:', person.name);
    console.log('RAW photo_url from API:', person.photo_url);
    console.log('RESOLVED photo URL:', photo);
  }

  return (
    <Link
      href={`/persons/${person.id}`}
      className="group flex items-center gap-3.5 py-4 focus-visible:outline-none"
    >
      <span className="hidden sm:block font-mono text-[10px] tracking-[0.2em] text-[var(--text-muted)] min-w-[22px] tabular-nums">
        {String(index + 1).padStart(2, '0')}
      </span>

      {/* Фото — компактная квадратная плитка */}
      <span
        aria-hidden="true"
        className={`shrink-0 overflow-hidden bg-[var(--bg-tertiary)] grid place-items-center font-serif text-[var(--text-muted)] transition-colors duration-500 ${
          prominent ? 'w-12 h-14 text-sm' : 'w-10 h-12 text-xs'
        }`}
      >
        {photo ? (
          <Image
            src={photo}
            alt={person.name}
            width={prominent ? 48 : 40}
            height={prominent ? 56 : 48}
            className="object-cover transition-transform duration-[1200ms] ease-[cubic-bezier(0.76,0,0.24,1)] group-hover:scale-[1.06]"
          />
        ) : (
          initials
        )}
      </span>

      <span className="flex-1 min-w-0 flex items-center justify-between gap-3">
        <span className="min-w-0 flex flex-col leading-tight">
          <span
            className={`font-serif text-[var(--text-primary)] truncate transition-[font-style] duration-300 group-hover:italic ${
              prominent ? 'text-base sm:text-lg' : 'text-sm sm:text-base'
            }`}
          >
            {person.name}
          </span>
          {character && (
            <span className="mt-1 font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)] truncate">
              {character}
            </span>
          )}
        </span>

        <ArrowUpRightIcon
          className="w-3.5 h-3.5 shrink-0 text-[var(--text-muted)] opacity-0 group-hover:opacity-100 transition-opacity duration-500"
          aria-hidden="true"
        />
      </span>
    </Link>
  );
}