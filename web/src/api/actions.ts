import { query, request } from "@app/api/transport";
import type {
  Applied,
  Ban,
  CurrentBan,
  Engine,
  File,
  Jail,
  Kind,
  LogPage,
  RegexResult,
  Result,
  Stats,
  Stock,
} from "@app/api/types";

/** Named mechanically from the route, so a call site and a handler find each other by grep. */

export const postAuthLogin = (body: { password: string }) =>
  request<void>("/api/auth/login", { method: "POST", body });

export const postAuthLogout = () =>
  request<void>("/api/auth/logout", { method: "POST" });

export const postAuthLogoutEverywhere = () =>
  request<void>("/api/auth/logout-everywhere", { method: "POST" });

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
