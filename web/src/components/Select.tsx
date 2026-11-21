import type { SelectHTMLAttributes } from "react";

import { ChevronDownIcon } from "@app/components/icons/Icon";
import { fieldLook, fieldSizes } from "@app/components/TextField";

/**
 * The platform's own select, dressed as a field, with the chevron the rest of the interface
 * uses rather than each browser's own. Width belongs to the caller.
 *
 * A height as well as a min-height: Mobile Safari replaces a select's min-height with its own.
 */
export function Select({
  className = "",
  children,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <span className={`relative inline-flex items-center ${className}`}>
      <select
        className={`${fieldLook} ${fieldSizes.field} h-10 w-full min-w-0 appearance-none pr-9`}
        {...props}
      >
        {children}
      </select>
      <ChevronDownIcon className="pointer-events-none absolute right-3 text-muted" />
    </span>
  );
}
