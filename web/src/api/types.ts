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

/** Who the web says this is: its version, and the label F2B_LABEL gives it, or "". */
export type Me = { ok: boolean; version: string; label: string };

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

/** What a save, a delete or a rename did: the file, the others changed with it, the reload. */
export type Applied = { file: File | null; also: FileRef[]; reload: Result };

export type Stock = { filters: string[]; actions: string[]; other: string[] };

/** What an API token may do on /api/v1. */
export type Scope = "read" | "write";

/** An API token as the web lists it: never its secret. Times are Unix seconds, 0 for never. */
export type Token = {
  id: string;
  name: string;
  scope: Scope;
  created: number;
  lastUsed: number;
  expires: number;
  /** Seconds it lasts unused. */
  idle: number;
  /** When it stops working at the latest, unused from now. */
  ends: number;
  expired: boolean;
};

/** How long a token lasts, and how long unused: the web's keys for them. */
export type Lifetime = "1d" | "1w" | "30d" | "90d" | "180d" | "1y" | "never";

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
