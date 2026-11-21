import { useMemo, useSyncExternalStore } from "react";

import type { Kind } from "@app/api/types";

/**
 * Where the app is, read from the address bar and nowhere else, so a reload or a copied link
 * lands on the same thing.
 */
export type Route =
  | { page: "overview"; days: number }
  | { page: "bans" }
  | { page: "history"; jail: string; ip: string }
  | { page: "config" }
  | { page: "file"; kind: Kind; name: string; fresh: boolean }
  | { page: "stock"; path: string }
  | { page: "log" }
  | { page: "missing" };

/** The windows the overview offers, in days. */
export const ranges = [7, 30, 90] as const;

export const defaultDays = 30;

const kinds: readonly Kind[] = ["jails", "filters", "actions", "settings"];

const enc = encodeURIComponent;

export const paths = {
  overview: (days: number = defaultDays) =>
    days === defaultDays ? "/" : `/?days=${days}`,
  bans: "/bans",
  history: (q: { jail?: string; ip?: string } = {}) => {
    const s = new URLSearchParams();
    if (q.jail) s.set("jail", q.jail);
    if (q.ip) s.set("ip", q.ip);
    const rendered = s.toString();
    return rendered ? `/history?${rendered}` : "/history";
  },
  config: "/config",
  /** fresh: a file not saved yet, opened with what a new one of its kind starts with. */
  file: (kind: Kind, name: string, fresh = false) =>
    `/config/${kind}/${enc(name)}${fresh ? "?new=1" : ""}`,
  stock: (path: string) => `/stock/${path.split("/").map(enc).join("/")}`,
  log: "/log",
};

/** A route from an address: its path, and its query. */
export function parse(address: string): Route {
  const at = address.indexOf("?");
  const path = at < 0 ? address : address.slice(0, at);
  const params = new URLSearchParams(at < 0 ? "" : address.slice(at + 1));
  let parts: string[];
  try {
    parts = path.split("/").filter(Boolean).map(decodeURIComponent);
  } catch {
    return { page: "missing" };
  }
  const [first, second, third] = parts;
  if (parts.length === 0) {
    const asked = Number(params.get("days"));
    const days = (ranges as readonly number[]).includes(asked)
      ? asked
      : defaultDays;
    return { page: "overview", days };
  }
  if (first === "bans" && parts.length === 1) return { page: "bans" };
  if (first === "history" && parts.length === 1) {
    return {
      page: "history",
      jail: params.get("jail") ?? "",
      ip: params.get("ip") ?? "",
    };
  }
  if (first === "log" && parts.length === 1) return { page: "log" };
  if (first === "config" && parts.length === 1) return { page: "config" };
  if (
    first === "config" &&
    parts.length === 3 &&
    kinds.includes(second as Kind)
  ) {
    return {
      page: "file",
      kind: second as Kind,
      name: third!,
      fresh: params.get("new") === "1",
    };
  }
  if (first === "stock" && parts.length >= 2) {
    return { page: "stock", path: parts.slice(1).join("/") };
  }
  return { page: "missing" };
}

const listeners = new Set<() => void>();

function subscribe(listener: () => void) {
  listeners.add(listener);
  window.addEventListener("popstate", listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("popstate", listener);
  };
}

const here = () => window.location.pathname + window.location.search;

/**
 * Something that would be lost by leaving: an editor with unsaved changes registers how to ask,
 * in the application's own dialog, and a move within the island waits for the answer. The
 * browser's own question covers leaving the document.
 */
let holding: (() => Promise<boolean>) | null = null;

export function hold(ask: (() => Promise<boolean>) | null) {
  holding = ask;
}

/** Moves within the island, as a link does, without loading another document. */
export async function go(address: string, replace = false) {
  if (address === here()) return;
  if (holding && !(await holding())) return;
  holding = null;
  if (replace) window.history.replaceState(null, "", address);
  else window.history.pushState(null, "", address);
  for (const listener of listeners) listener();
}

export function useRoute(): Route {
  const address = useSyncExternalStore(subscribe, here);
  return useMemo(() => parse(address), [address]);
}
