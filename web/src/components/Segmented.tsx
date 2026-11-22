import { useRef, type KeyboardEvent } from "react";

/**
 * One of a few, all in sight: two or three choices a select would hide behind a press. A radio
 * group, so a screen reader says which is chosen and of how many, and the arrows move between
 * them as they do between radios, the choice following; Tab goes past it as one stop.
 *
 * The width it stands in, each option an equal share. Under a Group rather than a Field: a
 * Field's label would take the first option for its own.
 */
export function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
  className = "",
}: {
  /** What is chosen, for a screen reader. */
  label: string;
  value: T;
  options: readonly { value: T; label: string }[];
  onChange: (value: T) => void;
  className?: string;
}) {
  const box = useRef<HTMLDivElement>(null);
  const keyDown = (e: KeyboardEvent<HTMLButtonElement>, i: number) => {
    const step =
      e.key === "ArrowRight" || e.key === "ArrowDown"
        ? 1
        : e.key === "ArrowLeft" || e.key === "ArrowUp"
          ? -1
          : 0;
    if (!step) return;
    e.preventDefault();
    const next = (i + step + options.length) % options.length;
    onChange(options[next]!.value);
    box.current?.querySelectorAll("button")[next]?.focus();
  };

  return (
    <div
      ref={box}
      role="radiogroup"
      aria-label={label}
      className={`flex min-h-8 w-full gap-0.5 rounded-md bg-control p-0.5 ${className}`}
    >
      {options.map((o, i) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={o.value === value}
          tabIndex={o.value === value ? 0 : -1}
          onClick={() => onChange(o.value)}
          onKeyDown={(e) => keyDown(e, i)}
          className="flex-1 rounded px-3 text-sm whitespace-nowrap text-muted hover:text-fg focus-visible:ring-1 focus-visible:ring-brand focus-visible:outline-none aria-checked:bg-bg aria-checked:text-fg aria-checked:shadow-sm"
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
