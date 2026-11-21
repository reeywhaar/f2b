import type { InputHTMLAttributes } from "react";

/** The look every typed-into control shares, for a select to wear as well. */
export const fieldLook =
  "rounded-md bg-control px-3 text-fg placeholder:text-faint focus:ring-1 focus:ring-brand focus:outline-none disabled:opacity-50";

/**
 * How tall, the same question a button's size answers, the same way: field in a form or a
 * dialog, bar on a page, where a field narrows what is shown beside buttons of that height, on a
 * phone too.
 */
export const fieldSizes = {
  field: "min-h-10 py-1.5",
  bar: "min-h-8 py-1",
} as const;

export type FieldSize = keyof typeof fieldSizes;

/** A field's frame, ground and focus. Width belongs to the caller. */
export function TextField({
  className = "",
  ...props
}: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={`${fieldLook} ${fieldSizes.field} ${className}`}
      {...props}
    />
  );
}
