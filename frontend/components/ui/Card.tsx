// frontend/components/ui/Card.tsx
'use client';

import {
  forwardRef,
  type HTMLAttributes,
  type ReactNode,
  type Ref,
} from 'react';
import Link from 'next/link';

type CardAs = 'div' | 'article' | 'section' | 'li' | 'aside';

export interface CardProps extends HTMLAttributes<HTMLElement> {
  children: ReactNode;
  interactive?: boolean;
  padding?: 'none' | 'sm' | 'md' | 'lg';
  flat?: boolean;
  elevated?: boolean;
  dashed?: boolean;
  as?: CardAs;
  href?: string;
  className?: string;
}

const PADDING_CLASS: Record<NonNullable<CardProps['padding']>, string> = {
  none: '',
  sm: 'p-4',
  md: 'p-6',
  lg: 'p-8 lg:p-10',
};

const FOCUS_CLASS =
  'focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--text-primary)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg-primary)]';

const Card = forwardRef<HTMLElement, CardProps>(function Card(
  {
    children,
    interactive = false,
    padding = 'md',
    flat = false,
    elevated = false,
    dashed = false,
    as: Tag = 'div',
    href,
    className = '',
    ...rest
  },
  ref
) {
  const isInteractive = interactive || !!href;

  const classes = [
    'relative bg-[var(--bg-primary)] text-[var(--text-primary)]',

    !flat &&
      (dashed
        ? 'border border-dashed border-[var(--line)]'
        : 'border border-[var(--line)]'),

    !flat &&
      elevated &&
      'before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-[2px] before:bg-[var(--accent-yellow)] before:content-[""]',

    PADDING_CLASS[padding],

    isInteractive &&
      'cursor-pointer transition-colors duration-500 ease-[cubic-bezier(0.76,0,0.24,1)] hover:border-[var(--text-primary)]',

    isInteractive && !href && FOCUS_CLASS,

    className,
  ]
    .filter(Boolean)
    .join(' ');

  if (href) {
    return (
      <Link
        ref={ref as Ref<HTMLAnchorElement>}
        href={href}
        className={`${classes} ${FOCUS_CLASS} group block`}
        {...rest}
      >
        {children}
      </Link>
    );
  }

  return (
    <Tag ref={ref as Ref<HTMLElement>} className={classes} {...rest}>
      {children}
    </Tag>
  );
});

Card.displayName = 'Card';
export default Card;