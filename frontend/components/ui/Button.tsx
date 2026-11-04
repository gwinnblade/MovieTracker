// frontend/components/ui/Button.tsx
'use client';

import {
  forwardRef,
  type ButtonHTMLAttributes,
  type ReactNode,
} from 'react';
import Link from 'next/link';
import { ArrowPathIcon } from '@heroicons/react/24/outline';

type Variant = 'primary' | 'secondary' | 'danger' | 'ghost';
type Size = 'sm' | 'md' | 'lg';

export interface ButtonProps
  extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'type'> {
  variant?: Variant;
  size?: Size;
  children?: ReactNode;
  loading?: boolean;
  loadingText?: string;
  leftIcon?: ReactNode;
  rightIcon?: ReactNode;
  fullWidth?: boolean;
  type?: 'button' | 'submit' | 'reset';
  href?: string;
}

const BASE =
  'inline-flex items-center justify-center font-mono uppercase tracking-[0.22em] leading-none whitespace-nowrap transition-[background-color,color,border-color,opacity] duration-500 ease-[cubic-bezier(0.76,0,0.24,1)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-yellow)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg-primary)] disabled:cursor-not-allowed disabled:opacity-40';

const VARIANT_CLASS: Record<Variant, string> = {
  primary:
    'bg-[var(--text-primary)] text-[var(--bg-primary)] border border-[var(--text-primary)] hover:opacity-85',
  secondary:
    'bg-transparent text-[var(--text-primary)] border border-[var(--line)] hover:border-[var(--text-primary)]',
  danger:
    'bg-transparent text-[var(--accent-red)] border border-[var(--accent-red)] hover:bg-[var(--accent-red)] hover:text-white',
  ghost:
    'bg-transparent text-[var(--text-muted)] border-0 hover:text-[var(--text-primary)] px-0',
};

const SIZE_CLASS: Record<Size, string> = {
  sm: 'text-[10px] px-3 py-2 gap-2',
  md: 'text-[10px] sm:text-[11px] px-4 py-2.5 gap-2.5',
  lg: 'text-[11px] px-6 py-3.5 gap-3',
};

const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = 'secondary',
    size = 'md',
    children,
    className = '',
    disabled,
    loading = false,
    loadingText,
    leftIcon,
    rightIcon,
    fullWidth = false,
    type = 'button',
    href,
    ...rest
  },
  ref
) {
  const isDisabled = disabled || loading;

  // Ghost-вариант не получает паддинги по умолчанию — это «текстовая» ссылка
  const sizeClass = variant === 'ghost' ? '' : SIZE_CLASS[size];

  const classes = [
    BASE,
    VARIANT_CLASS[variant],
    sizeClass,
    fullWidth ? 'w-full' : '',
    className,
  ]
    .filter(Boolean)
    .join(' ');

  const label = loading && loadingText ? loadingText : children;

  const content = (
    <>
      {loading ? (
        <ArrowPathIcon
          className="w-3.5 h-3.5 animate-spin shrink-0"
          aria-hidden="true"
        />
      ) : leftIcon ? (
        <span aria-hidden="true" className="inline-flex shrink-0">
          {leftIcon}
        </span>
      ) : null}

      {label != null && label !== '' && (
        <span className="inline-block">{label}</span>
      )}

      {rightIcon && !loading && (
        <span
          aria-hidden="true"
          className="inline-flex shrink-0 transition-transform duration-500 group-hover:translate-x-0.5"
        >
          {rightIcon}
        </span>
      )}
    </>
  );

  if (href) {
    return (
      <Link
        href={href}
        className={`group ${classes}`}
        aria-disabled={isDisabled || undefined}
        aria-busy={loading || undefined}
        onClick={(e) => {
          if (isDisabled) e.preventDefault();
        }}
      >
        {content}
      </Link>
    );
  }

  return (
    <button
      ref={ref}
      type={type}
      className={`group ${classes}`}
      disabled={isDisabled}
      aria-busy={loading || undefined}
      {...rest}
    >
      {content}
    </button>
  );
});

Button.displayName = 'Button';
export default Button;