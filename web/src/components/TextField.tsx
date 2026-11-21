import type { InputHTMLAttributes } from "react";

/** The look every typed-into control shares, for a select to wear as well. */
export const fieldLook =
  "rounded-md bg-control px-3 text-fg placeholder:text-faint focus:ring-1 focus:ring-brand focus:outline-none disabled:opacity-50";

/** One height for every field, select and picker, the buttons' too, wherever it stands. */
export const fieldHeight = "min-h-8 py-1";

/** A field's frame, ground and focus. Width belongs to the caller. */
export function TextField({
  className = "",
  ...props
}: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input className={`${fieldLook} ${fieldHeight} ${className}`} {...props} />
  );
}
