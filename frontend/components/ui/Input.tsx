// frontend/components/ui/Input.tsx
import {
  forwardRef,
  useId,
  type InputHTMLAttributes,
  type ReactNode,
} from 'react';

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  hint?: string;
  leftIcon?: ReactNode;
  rightSlot?: ReactNode;
  wrapperClassName?: string;
}

const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  {
    label,
    error,
    hint,
    leftIcon,
    rightSlot,
    id,
    type = 'text',
    disabled,
    className = '',
    wrapperClassName = '',
    ...props
  },
  ref
) {
  const reactId = useId();
  const inputId = id ?? `input-${reactId}`;
  const errorId = `${inputId}-error`;
  const hintId = `${inputId}-hint`;

  const describedBy =
    [error ? errorId : hint ? hintId : null].filter(Boolean).join(' ') || undefined;

  return (
    <div className={`flex flex-col ${wrapperClassName}`}>
      {label && (
        <label
          htmlFor={inputId}
          className="block font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] mb-1.5"
        >
          {label}
        </label>
      )}

      <div
        className={`relative flex items-center gap-2 border-b transition-colors duration-500 ${
          disabled
            ? 'border-[var(--line)]/60'
            : error
              ? 'border-[var(--accent-red)]'
              : 'border-[var(--line)] focus-within:border-[var(--accent-yellow)]'
        }`}
      >
        {leftIcon && (
          <span
            aria-hidden="true"
            className="shrink-0 inline-flex text-[var(--text-muted)] pointer-events-none"
          >
            {leftIcon}
          </span>
        )}

        <input
          ref={ref}
          id={inputId}
          type={type}
          disabled={disabled}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          className={`flex-1 min-w-0 bg-transparent border-0 outline-none px-0 py-2.5 font-serif text-base sm:text-lg tracking-[-0.005em] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] placeholder:italic placeholder:opacity-60 disabled:opacity-50 disabled:cursor-not-allowed ${className}`}
          {...props}
        />

        {rightSlot && (
          <span className="shrink-0 inline-flex items-center">
            {rightSlot}
          </span>
        )}
      </div>

      {error ? (
        <p
          id={errorId}
          role="alert"
          className="mt-2 font-mono text-[10px] uppercase tracking-[0.15em] text-[var(--accent-red)] leading-snug"
        >
          {error}
        </p>
      ) : hint ? (
        <p
          id={hintId}
          className="mt-2 font-mono text-[10px] uppercase tracking-[0.12em] text-[var(--text-muted)] leading-snug"
        >
          {hint}
        </p>
      ) : null}
    </div>
  );
});

Input.displayName = 'Input';
export default Input;