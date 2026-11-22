import { query, request } from "@app/api/transport";
import type {
  Applied,
  Ban,
  CurrentBan,
  Engine,
  File,
  FileRef,
  Jail,
  Kind,
  LogDir,
  LogEntry,
  LogPage,
  Me,
  RegexResult,
  Result,
  Lifetime,
  Scope,
  Stats,
  Stock,
  Token,
} from "@app/api/types";

/** Named mechanically from the route, so a call site and a handler find each other by grep. */

export const postAuthLogin = (body: { password: string }) =>
  request<void>("/api/auth/login", { method: "POST", body });

export const postAuthLogout = () =>
  request<void>("/api/auth/logout", { method: "POST" });

export const postAuthLogoutEverywhere = () =>
  request<void>("/api/auth/logout-everywhere", { method: "POST" });

export const getAuthMe = () => request<Me>("/api/auth/me");

export const getAuthTokens = () =>
  request<{ tokens: Token[] }>("/api/auth/tokens");

/** Issues a token; secret is the whole of it, in this answer and nowhere else. */
export const postAuthTokens = (body: {
  name: string;
  scope: Scope;
  expiresIn: Lifetime;
  idleFor: Lifetime;
}) =>
  request<{ token: Token; secret: string }>("/api/auth/tokens", {
    method: "POST",
    body,
  });

export const deleteAuthTokensById = (id: string) =>
  request<void>(`/api/auth/tokens/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });

export const getEngine = () => request<Engine>("/api/engine");

export const postEngineRestart = () =>
  request<void>("/api/engine/restart", { method: "POST" });

export const getJails = () => request<{ jails: Jail[] }>("/api/jails");

export const getBans = () => request<{ bans: CurrentBan[] }>("/api/bans");

export const postBans = (body: { jail: string; ip: string }) =>
  request<void>("/api/bans", { method: "POST", body });

/** Lifts a ban in one jail, or in every jail when jail is not given. */
export const deleteBansByIp = (ip: string, jail?: string) =>
  request<void>(`/api/bans/${encodeURIComponent(ip)}${query({ jail })}`, {
    method: "DELETE",
  });

export const getHistory = (q: {
  jail?: string;
  ip?: string;
  before?: number;
  limit?: number;
}) => request<{ bans: Ban[]; next: number }>(`/api/history${query(q)}`);

export const getStats = (days: number) =>
  request<Stats>(`/api/stats${query({ days })}`);

export const getFiles = () => request<{ files: File[] }>("/api/files");

const filePath = (kind: Kind, name: string) =>
  `/api/files/${kind}/${encodeURIComponent(name)}`;

export const getFile = (kind: Kind, name: string) =>
  request<{ file: File; content: string }>(filePath(kind, name));

/** version is the one the content was edited from, or "" for a new file. */
export const putFile = (
  kind: Kind,
  name: string,
  body: { content: string; version: string },
) => request<Applied>(filePath(kind, name), { method: "PUT", body });

export const deleteFile = (kind: Kind, name: string, version: string) =>
  request<Applied>(`${filePath(kind, name)}${query({ version })}`, {
    method: "DELETE",
  });

/** The jail files that name this filter or action. */
export const getFileReferences = (kind: Kind, name: string) =>
  request<{ files: FileRef[] }>(`${filePath(kind, name)}/references`);

/** Moves a file to a new name; with references, the jails naming it name the new one. */
export const postFileRename = (
  kind: Kind,
  name: string,
  body: { to: string; version: string; references: boolean },
) =>
  request<Applied>(`${filePath(kind, name)}/rename`, { method: "POST", body });

/** Whether fail2ban would start with this change, without making it. */
export const postCheck = (body: {
  kind: Kind;
  name: string;
  content: string | null;
}) => request<Result>("/api/check", { method: "POST", body });

export const getStock = () => request<Stock>("/api/stock");

export const getStockFile = (path: string) =>
  request<{ path: string; content: string }>(
    `/api/stock/${path.split("/").map(encodeURIComponent).join("/")}`,
  );

export const getLogs = () => request<{ roots: LogEntry[] }>("/api/logs");

/** Every file among the logs, as far as the engine looks: more says it stopped short. */
export const getLogFiles = () =>
  request<{ roots: LogEntry[]; files: LogEntry[]; more: boolean }>(
    "/api/logs?files=1",
  );

/** A directory or a file among the logs; with tail, a file's last that many lines too. */
export const getLogsByPath = (path: string, tail?: number) =>
  request<LogDir>(
    `/api/logs/${path.replace(/^\//, "").split("/").map(encodeURIComponent).join("/")}${query({ tail })}`,
  );

export const postRegex = (body: {
  filter: string;
  file?: string;
  content?: string;
  log?: string;
  text?: string;
  lines?: number;
}) => request<RegexResult>("/api/regex", { method: "POST", body });

export const getLog = (after: number, epoch: string) =>
  request<LogPage>(
    `/api/log${query({ after: after < 0 ? undefined : after, epoch, limit: after < 0 ? 2000 : undefined })}`,
  );
