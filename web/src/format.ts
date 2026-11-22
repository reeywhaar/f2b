/**
 * Times and counts as a person reads them. Times arrive as Unix seconds and are shown in the
 * browser's own zone.
 */

const units: [number, string][] = [
  [7 * 86400, "w"],
  [86400, "d"],
  [3600, "h"],
  [60, "m"],
  [1, "s"],
];

/** A span of seconds, in its two largest units: "1d 4h", "12m", "45s". -1 is for good. */
export function span(seconds: number): string {
  if (seconds < 0) return "for good";
  if (seconds === 0) return "0s";
  const parts: string[] = [];
  let left = Math.round(seconds);
  for (const [length, unit] of units) {
    if (left >= length) {
      parts.push(`${Math.floor(left / length)}${unit}`);
      left %= length;
    }
    if (parts.length === 2) break;
  }
  return parts.join(" ");
}

/** How long ago, roughly: "just now", "5m ago", "3h ago", "2d ago". */
export function ago(at: number, now = Date.now() / 1000): string {
  const d = now - at;
  if (d < 45) return "just now";
  return `${span(d).split(" ")[0]} ago`;
}

/** How long until, roughly: "in 3h". */
export function until(at: number, now = Date.now() / 1000): string {
  const d = at - now;
  if (d <= 0) return "now";
  return `in ${span(d).split(" ")[0]}`;
}

const dateTimeFormat = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});

const dayFormat = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  timeZone: "UTC",
});

/** A moment in full: "Nov 21, 2026, 10:42". */
export function dateTime(at: number): string {
  return dateTimeFormat.format(new Date(at * 1000));
}

/** A UTC day, "2026-11-21", as "Nov 21": the engine counts days in UTC. */
export function day(iso: string): string {
  return dayFormat.format(new Date(`${iso}T00:00:00Z`));
}

const counts = new Intl.NumberFormat();

export function count(n: number): string {
  return counts.format(n);
}

/** Bytes, for a file's size: a filter in bytes, a log in gigabytes. */
export function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const scale = ["KB", "MB", "GB", "TB"];
  let n = bytes / 1024;
  let i = 0;
  while (n >= 1024 && i < scale.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(n < 10 ? 1 : 0)} ${scale[i]}`;
}
