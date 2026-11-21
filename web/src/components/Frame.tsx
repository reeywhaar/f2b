import type { ReactNode } from "react";

/**
 * A page's frame: the same width and gutters on every page, and the header's gutters, so the
 * name above and the page below start at one edge.
 */
export function Frame({
  fill = false,
  children,
}: {
  /**
   * Takes the height left under the header, for a page whose content scrolls inside it, and ends
   * the gutter's width from the bottom of the screen, as from its sides.
   */
  fill?: boolean;
  children: ReactNode;
}) {
  return (
    <main
      className={`mx-auto flex w-full max-w-7xl flex-col gap-8 px-2 pt-6 sm:px-4 ${fill ? "min-h-0 flex-1 pb-2 sm:pb-4" : "pb-6"}`}
    >
      {children}
    </main>
  );
}
