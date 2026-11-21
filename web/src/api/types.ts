/** The engine's answers, as docs/api.md describes them. Times are Unix seconds. */

export type DaemonState = {
  state: "starting" | "running" | "stopped";
  version: string;
  pid: number;
  since: number;
  restarts: number;
  lastExit: string;
};

export type Engine = { version: string; fail2ban: DaemonState };

export type Kind = "jails" | "filters" | "actions" | "settings";

export type FileRef = { kind: Kind; name: string };

export type Jail = {
  name: string;
  failedNow: number;
  failedTotal: number;
  bannedNow: number;
  bannedTotal: number;
  logs: string[];
  findTime: number;
  banTime: number;
  maxRetry: number;
  file: FileRef | null;
  /** The filter it names, without options, or its own name. */
  filter: string;
};

export type Ban = {
  id: number;
  jail: string;
  ip: string;
  at: number;
  /** Seconds; -1 is for good. */
  duration: number;
  count: number;
  failures: number;
  matches: string[];
};

/** A ban in force; until is 0 for for good, or when the database does not say. */
export type CurrentBan = Ban & { until: number };

export type Stats = {
  days: number;
  from: number;
  jails: string[];
  perDay: { day: string; total: number; byJail: Record<string, number> }[];
  bans: number;
  ips: number;
  repeat: number;
  lastDay: number;
  top: { ip: string; bans: number; last: number; jails: string[] }[];
};

export type File = {
  kind: Kind;
  name: string;
  size: number;
  modified: number;
  version: string;
  sections: string[];
};

export type Result = { ok: boolean; output: string };

export type Applied = { file: File | null; reload: Result };

export type Stock = { filters: string[]; actions: string[]; other: string[] };

export type RegexResult = {
  ok: boolean;
  output: string;
  summary: {
    lines: number;
    ignored: number;
    matched: number;
    missed: number;
  } | null;
};

export type LogPage = {
  epoch: string;
  last: number;
  lines: { seq: number; text: string }[];
};
