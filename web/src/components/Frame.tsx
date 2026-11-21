import type { ReactNode } from "react";

/** A page's frame: the same width and gutters on every page. */
export function Frame({ children }: { children: ReactNode }) {
  return (
    <main className="mx-auto flex w-full max-w-7xl flex-col gap-8 px-4 py-6">
      {children}
    </main>
  );
}
