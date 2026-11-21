import { useMemo, useState, type KeyboardEvent } from "react";

import { Dialog } from "@app/components/Dialog";
import { CheckIcon, ChevronDownIcon } from "@app/components/icons/Icon";
import { SearchField } from "@app/components/SearchField";
import {
  fieldLook,
  fieldSizes,
  type FieldSize,
} from "@app/components/TextField";

export type Option = { value: string; label: string };

/**
 * One choice among many, in a dialog with a field to find it by, rather than a select: a select
 * of two hundred jails is a scroll through two hundred jails. Enter takes the first that matches.
 */
export function Picker({
  label,
  value,
  options,
  onChange,
  size = "field",
  className = "",
}: {
  /** What is being chosen, for the dialog's title and for a screen reader. */
  label: string;
  value: string;
  options: Option[];
  onChange: (value: string) => void;
  size?: FieldSize;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const [find, setFind] = useState("");
  const current = options.find((o) => o.value === value);
  const shown = useMemo(() => {
    const f = find.trim().toLowerCase();
    return f
      ? options.filter((o) => o.label.toLowerCase().includes(f))
      : options;
  }, [options, find]);

  const choose = (v: string) => {
    setOpen(false);
    setFind("");
    if (v !== value) onChange(v);
  };
  const keyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && shown[0]) {
      e.preventDefault();
      choose(shown[0].value);
    }
  };

  // A button dressed as a field, so it takes a field's type size, which main.css gives inputs:
  // 16px on a phone, where less makes iOS zoom into a focused field, and 14px past that.
  return (
    <>
      <button
        type="button"
        aria-label={`${label}: ${current?.label ?? value}`}
        aria-haspopup="dialog"
        onClick={() => setOpen(true)}
        className={`${fieldLook} ${fieldSizes[size]} inline-flex items-center gap-2 text-left text-base sm:text-sm ${className}`}
      >
        <span className="min-w-0 flex-1 truncate">
          {current?.label ?? value}
        </span>
        <ChevronDownIcon className="shrink-0 text-muted" />
      </button>
      <Dialog
        open={open}
        onClose={() => {
          setOpen(false);
          setFind("");
        }}
        title={label}
      >
        <SearchField
          data-autofocus
          placeholder="Find"
          aria-label={`Find a ${label.toLowerCase()}`}
          className="w-full"
          value={find}
          onChange={setFind}
          onKeyDown={keyDown}
        />
        {shown.length === 0 ? (
          <p className="text-sm text-muted">Nothing by that name.</p>
        ) : (
          <ul className="-mx-2 flex flex-col">
            {shown.map((o) => (
              <li key={o.value}>
                <button
                  type="button"
                  aria-pressed={o.value === value}
                  onClick={() => choose(o.value)}
                  className="flex w-full items-center gap-2 rounded-md px-2 py-2 text-left text-sm hover:bg-fill aria-pressed:font-medium"
                >
                  <span className="min-w-0 flex-1 truncate">{o.label}</span>
                  {o.value === value ? (
                    <CheckIcon className="text-brand" />
                  ) : null}
                </button>
              </li>
            ))}
          </ul>
        )}
      </Dialog>
    </>
  );
}
