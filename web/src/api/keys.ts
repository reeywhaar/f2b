import type { Kind } from "@app/api/types";

/** Every query key, in one object, so what one change makes stale is found by prefix. */
export const qk = {
  engine: ["engine"] as const,
  jails: ["jails"] as const,
  bans: ["bans"] as const,
  /** Under history, so a ban or an unban makes every page and count of it stale. */
  history: ["history"] as const,
  historyPage: (jail: string, ip: string) =>
    ["history", "page", jail, ip] as const,
  stats: (days: number) => ["history", "stats", days] as const,
  files: ["files"] as const,
  file: (kind: Kind, name: string) => ["files", kind, name] as const,
  /** Under the file, so whatever makes the file stale makes this stale too. */
  fileReferences: (kind: Kind, name: string) =>
    ["files", kind, name, "references"] as const,
  stock: ["stock"] as const,
  stockFile: (path: string) => ["stock", path] as const,
};
