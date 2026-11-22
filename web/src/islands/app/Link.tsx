import type { ComponentProps, MouseEvent } from "react";

import { go } from "@app/islands/app/route";

/**
 * A real link, so it can be opened in a new tab, copied and read aloud as one, that moves within
 * the island on a plain click. With replace, it takes the place of where it was, as narrowing a
 * list does, rather than leaving a step to go back through.
 */
export function Link({
  href,
  replace = false,
  onClick,
  ...props
}: ComponentProps<"a"> & { href: string; replace?: boolean }) {
  const click = (e: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(e);
    if (e.defaultPrevented || e.button !== 0) return;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    go(href, replace);
  };
  return <a href={href} onClick={click} {...props} />;
}
