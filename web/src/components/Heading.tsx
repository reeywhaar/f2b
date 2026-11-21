import type { ReactNode } from "react";

/** A section's name on a page of sections: small, upper case, and the same everywhere. */
export function Heading({
  children,
  className = "mb-2",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <h2
      className={`text-sm font-semibold tracking-wide uppercase ${className}`}
    >
      {children}
    </h2>
  );
}
