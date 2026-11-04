// frontend/components/ui/Badge.tsx
import {
  forwardRef,
  type HTMLAttributes,
  type ReactNode,
} from 'react';

type BadgeColor =
  | 'yellow'
  | 'pink'
  | 'green'
  | 'purple'
  | 'blue'
  | 'orange'
  | 'red'
  | 'gray';

type BadgeSize = 'xs' | 'sm' | 'md';
type BadgeVariant = 'solid' | 'outline' | 'subtle';

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  children: ReactNode;
  color?: BadgeColor;
  size?: BadgeSize;
  variant?: BadgeVariant;
  dot?: boolean;
  icon?: ReactNode;
}

const SIZE_CLASSES: Record<BadgeSize, string> = {
  xs: 'text-[9px] tracking-[0.18em] px-1.5 py-0.5 gap-1.5',
  sm: 'text-[10px] tracking-[0.16em] px-2 py-0.5 gap-1.5',
  md: 'text-[10px] tracking-[0.18em] px-2.5 py-1 gap-2',
};

const ACCENT_VAR: Record<BadgeColor, string> = {
  yellow: 'var(--accent-yellow)',
  pink: 'var(--accent-pink)',
  green: 'var(--accent-green)',
  purple: 'var(--accent-purple)',
  blue: 'var(--accent-blue)',
  orange: 'var(--accent-orange)',
  red: 'var(--accent-red)',
  gray: 'var(--text-muted)',
};

const SOLID_CLASSES: Record<BadgeColor, string> = {
  yellow: 'text-[var(--text-primary)] border-l-[2px] border-[var(--accent-yellow)] pl-2',
  pink: 'text-[var(--text-primary)] border-l-[2px] border-[var(--accent-pink)] pl-2',
  green: 'text-[var(--text-primary)] border-l-[2px] border-[var(--accent-green)] pl-2',
  purple: 'text-[var(--text-primary)] border-l-[2px] border-[var(--accent-purple)] pl-2',
  blue: 'text-[var(--text-primary)] border-l-[2px] border-[var(--accent-blue)] pl-2',
  orange: 'text-[var(--text-primary)] border-l-[2px] border-[var(--accent-orange)] pl-2',
  red: 'text-[var(--text-primary)] border-l-[2px] border-[var(--accent-red)] pl-2',
  gray: 'text-[var(--text-primary)] border-l-[2px] border-[var(--line)] pl-2',
};

const OUTLINE_CLASSES: Record<BadgeColor, string> = {
  yellow: 'bg-transparent text-[var(--accent-yellow)] border border-[var(--accent-yellow)]',
  pink: 'bg-transparent text-[var(--accent-pink)] border border-[var(--accent-pink)]',
  green: 'bg-transparent text-[var(--accent-green)] border border-[var(--accent-green)]',
  purple: 'bg-transparent text-[var(--accent-purple)] border border-[var(--accent-purple)]',
  blue: 'bg-transparent text-[var(--accent-blue)] border border-[var(--accent-blue)]',
  orange: 'bg-transparent text-[var(--accent-orange)] border border-[var(--accent-orange)]',
  red: 'bg-transparent text-[var(--accent-red)] border border-[var(--accent-red)]',
  gray: 'bg-transparent text-[var(--text-secondary)] border border-[var(--line)]',
};

const SUBTLE_CLASSES: Record<BadgeColor, string> = {
  yellow: 'bg-transparent text-[var(--accent-yellow)]',
  pink: 'bg-transparent text-[var(--accent-pink)]',
  green: 'bg-transparent text-[var(--accent-green)]',
  purple: 'bg-transparent text-[var(--accent-purple)]',
  blue: 'bg-transparent text-[var(--accent-blue)]',
  orange: 'bg-transparent text-[var(--accent-orange)]',
  red: 'bg-transparent text-[var(--accent-red)]',
  gray: 'bg-transparent text-[var(--text-secondary)]',
};

function getVariantClass(color: BadgeColor, variant: BadgeVariant): string {
  if (variant === 'outline') return OUTLINE_CLASSES[color];
  if (variant === 'subtle') return SUBTLE_CLASSES[color];
  return SOLID_CLASSES[color];
}

const Badge = forwardRef<HTMLSpanElement, BadgeProps>(function Badge(
  {
    children,
    color = 'gray',
    size = 'md',
    variant = 'solid',
    dot = false,
    icon,
    className = '',
    ...rest
  },
  ref
) {
  const classes = [
    'inline-flex items-center whitespace-nowrap align-middle font-mono font-medium uppercase leading-none',
    SIZE_CLASSES[size],
    getVariantClass(color, variant),
    className,
  ]
    .filter(Boolean)
    .join(' ');


  const showDot = dot || (variant !== 'outline' && color !== 'gray');

  return (
    <span ref={ref} className={classes} {...rest}>
      {showDot && (
        <span
          aria-hidden="true"
          className="w-[4px] h-[4px] rounded-full shrink-0"
          style={{ background: ACCENT_VAR[color] }}
        />
      )}
      {icon && (
        <span aria-hidden="true" className="shrink-0 inline-flex">
          {icon}
        </span>
      )}
      <span className="inline-block translate-y-[-0.03em]">{children}</span>
    </span>
  );
});

export default Badge;