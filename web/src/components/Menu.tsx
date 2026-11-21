import { useEffect, useRef, useState } from "react";

import { Button } from "@app/components/Button";
import { DotsIcon } from "@app/components/icons/Icon";

export type MenuItem = {
  label: string;
  onSelect: () => void;
  danger?: boolean;
  disabled?: boolean;
  /** Why it is disabled, when it is. */
  title?: string;
};

/**
 * Commands used now and then, behind one button, so the ones used all the time have the row to
 * themselves. Opens under the button, aligned to its right edge: it sits at the right of a row.
 * A press outside or Escape closes it.
 */
export function Menu({ label, items }: { label: string; items: MenuItem[] }) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const outside = (e: PointerEvent) => {
      if (!box.current?.contains(e.target as Node)) setOpen(false);
    };
    const escape = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", outside);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("pointerdown", outside);
      document.removeEventListener("keydown", escape);
    };
  }, [open]);

  return (
    <div ref={box} className="relative">
      <Button
        size="bar"
        aria-label={label}
        title={label}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        <DotsIcon className="text-base" />
      </Button>
      {open ? (
        <div
          role="menu"
          aria-label={label}
          className="absolute right-0 z-20 mt-1 flex min-w-44 flex-col rounded-lg border border-line bg-bg p-1 shadow-lg"
        >
          {items.map((item) => (
            <button
              key={item.label}
              type="button"
              role="menuitem"
              disabled={item.disabled}
              title={item.title}
              onClick={() => {
                setOpen(false);
                item.onSelect();
              }}
              className={`rounded-md px-3 py-2 text-left text-sm whitespace-nowrap hover:bg-fill disabled:opacity-50 disabled:hover:bg-transparent pointer-coarse:py-2.5 ${item.danger ? "text-accent" : ""}`}
            >
              {item.label}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}
