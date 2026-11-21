import type { ReactNode } from "react";

/**
 * A page's frame: the same width and gutters on every page, and the header's gutters, so the
 * name above and the page below start at one edge.
 */
export function Frame({ children }: { children: ReactNode }) {
  return (
    <main className="mx-auto flex w-full max-w-7xl flex-col gap-8 px-2 py-6 sm:px-4">
      {children}
    </main>
  );
}
