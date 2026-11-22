import { useMemo, useState, type KeyboardEvent, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";

import { getLogs, getLogsByPath } from "@app/api/actions";
import { qk } from "@app/api/keys";
import { messageOf } from "@app/api/transport";
import type { Jail, LogEntry } from "@app/api/types";
import { Dialog } from "@app/components/Dialog";
import {
  CheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  FileIcon,
  FolderIcon,
  PencilIcon,
} from "@app/components/icons/Icon";
import { SearchField } from "@app/components/SearchField";
import { fieldHeight, fieldLook } from "@app/components/TextField";
import { ago, count, dateTime, size } from "@app/format";

/** The tester's lines come from a log, by its path, or from what is pasted. */
export const PASTED = "text";

/**
 * Where the tester's lines come from, in a dialog rather than a select: the logs the jails read,
 * to find among however many jails there are, the directories the engine reads logs from, to go
 * through, or lines pasted.
 */
export function LogPicker({
  value,
  onChange,
  jails,
  className = "",
}: {
  /** A log's path, or PASTED. */
  value: string;
  onChange: (value: string) => void;
  jails: Jail[];
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const readers = useMemo(() => readersOf(jails), [jails]);
  const by = readers.get(value) ?? [];

  return (
    <>
      <button
        type="button"
        aria-label={`Lines from: ${value === PASTED ? "lines pasted here" : value}`}
        aria-haspopup="dialog"
        onClick={() => setOpen(true)}
        className={`${fieldLook} ${fieldHeight} inline-flex items-center gap-2 text-left text-base sm:text-sm ${className}`}
      >
        <span className="min-w-0 flex-1 truncate">
          {value === PASTED ? (
            "Lines pasted here"
          ) : (
            <>
              <span className="font-mono">{value}</span>
              {by.length ? (
                <span className="text-muted"> · {by.join(", ")}</span>
              ) : null}
            </>
          )}
        </span>
        <ChevronDownIcon className="shrink-0 text-muted" />
      </button>
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title="Lines from"
        wide
      >
        <Browser
          value={value}
          readers={readers}
          choose={(v) => {
            setOpen(false);
            if (v !== value) onChange(v);
          }}
        />
      </Dialog>
    </>
  );
}

/** Each log the jails read, and which jails read it, in the order the jails come. */
function readersOf(jails: Jail[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const j of jails) {
    for (const l of j.logs) out.set(l, [...(out.get(l) ?? []), j.name]);
  }
  return out;
}

/** Where a directory is, from the top: the place it is in, then each directory down to it. */
type Place = { root: string; dir: string };

function Browser({
  value,
  readers,
  choose,
}: {
  value: string;
  readers: Map<string, string[]>;
  choose: (value: string) => void;
}) {
  const [find, setFind] = useState("");
  const [at, setAt] = useState<Place | null>(null);
  const go = (p: Place | null) => {
    setAt(p);
    setFind("");
  };
  // Each view draws the field, as each knows what Enter takes: the first row it shows.
  const search: Search = (placeholder, enter) => (
    <SearchField
      data-autofocus
      placeholder={placeholder}
      aria-label={placeholder}
      className="w-full"
      value={find}
      onChange={setFind}
      onKeyDown={(e: KeyboardEvent<HTMLInputElement>) => {
        if (e.key === "Enter" && enter) {
          e.preventDefault();
          enter();
        }
      }}
    />
  );
  return at ? (
    <Directory
      at={at}
      find={find}
      search={search}
      value={value}
      choose={choose}
      go={go}
    />
  ) : (
    <Top
      find={find}
      search={search}
      value={value}
      readers={readers}
      choose={choose}
      go={go}
    />
  );
}

type Search = (placeholder: string, enter?: () => void) => ReactNode;

function Top({
  find,
  search,
  value,
  readers,
  choose,
  go,
}: {
  find: string;
  search: Search;
  value: string;
  readers: Map<string, string[]>;
  choose: (value: string) => void;
  go: (p: Place) => void;
}) {
  const roots = useQuery({ queryKey: qk.logs, queryFn: getLogs });
  const f = find.trim().toLowerCase();
  const typed = find.trim().startsWith("/") ? find.trim() : "";
  const logs = [...readers].filter(
    ([path, jails]) =>
      !f ||
      path.toLowerCase().includes(f) ||
      jails.some((j) => j.toLowerCase().includes(f)),
  );
  const places = (roots.data?.roots ?? []).filter(
    (r) => !f || r.path.toLowerCase().includes(f),
  );
  const pasted = !f || "lines pasted here".includes(f);
  const open = (e: LogEntry) =>
    e.dir ? () => go({ root: e.path, dir: e.path }) : () => choose(e.path);

  const log = logs[0]?.[0];
  const place = places[0];
  const enter = typed
    ? () => choose(typed)
    : log
      ? () => choose(log)
      : place
        ? open(place)
        : pasted
          ? () => choose(PASTED)
          : undefined;

  return (
    <div className="flex flex-col gap-4">
      {search("Find a log or a jail, or type a path", enter)}
      {typed ? (
        <Rows>
          <Row icon={<FileIcon />} onClick={() => choose(typed)}>
            Read <span className="font-mono">{typed}</span>
          </Row>
        </Rows>
      ) : null}
      {logs.length ? (
        <Section title="Read by a jail">
          <Rows>
            {logs.map(([path, jails]) => (
              <Row
                key={path}
                icon={<FileIcon />}
                pressed={path === value}
                onClick={() => choose(path)}
                aside={jails.join(", ")}
              >
                <span className="font-mono">{path}</span>
              </Row>
            ))}
          </Rows>
        </Section>
      ) : null}
      <Section
        title="Log directories"
        note="What is mounted into the engine read-only, and where the running jails read their logs."
      >
        {roots.isPending ? (
          <p className="text-sm text-muted">Reading…</p>
        ) : roots.isError ? (
          <p className="text-sm text-accent">{messageOf(roots.error)}</p>
        ) : places.length ? (
          <Rows>
            {places.map((r) => (
              <Row
                key={r.path}
                icon={r.dir ? <FolderIcon /> : <FileIcon />}
                pressed={r.path === value}
                onClick={open(r)}
                aside={r.dir ? undefined : size(r.size)}
                into={r.dir}
              >
                <span className="font-mono">{r.path}</span>
              </Row>
            ))}
          </Rows>
        ) : (
          <p className="text-sm text-muted">
            {f
              ? "None by that name."
              : "None: nothing is mounted read-only, and no jail is running."}
          </p>
        )}
      </Section>
      {pasted ? (
        <Rows>
          <Row
            icon={<PencilIcon />}
            pressed={value === PASTED}
            onClick={() => choose(PASTED)}
          >
            Lines pasted here
          </Row>
        </Rows>
      ) : null}
    </div>
  );
}

function Directory({
  at,
  find,
  search,
  value,
  choose,
  go,
}: {
  at: Place;
  find: string;
  search: Search;
  value: string;
  choose: (value: string) => void;
  go: (p: Place | null) => void;
}) {
  const dir = useQuery({
    queryKey: qk.logDir(at.dir),
    queryFn: () => getLogsByPath(at.dir),
  });
  const f = find.trim().toLowerCase();
  const shown = (dir.data?.entries ?? []).filter(
    (e) => !f || e.name.toLowerCase().includes(f),
  );
  const open = (e: LogEntry) =>
    e.dir ? () => go({ root: at.root, dir: e.path }) : () => choose(e.path);

  return (
    <div className="flex flex-col gap-2">
      {search("Find in this directory", shown[0] ? open(shown[0]) : undefined)}
      <Crumbs at={at} go={go} />
      {dir.isPending ? (
        <p className="text-sm text-muted">Reading…</p>
      ) : dir.isError ? (
        <p className="text-sm text-accent">{messageOf(dir.error)}</p>
      ) : shown.length ? (
        <Rows>
          {shown.map((e) => (
            <Row
              key={e.path}
              icon={e.dir ? <FolderIcon /> : <FileIcon />}
              pressed={e.path === value}
              onClick={open(e)}
              into={e.dir}
              aside={
                e.dir ? undefined : (
                  <>
                    {e.jails.length ? `${e.jails.join(", ")} · ` : ""}
                    {size(e.size)} ·{" "}
                    <span title={dateTime(e.modified)}>{ago(e.modified)}</span>
                  </>
                )
              }
            >
              <span className="font-mono">{e.name}</span>
            </Row>
          ))}
        </Rows>
      ) : (
        <p className="text-sm text-muted">
          {f ? "Nothing by that name here." : "Nothing here."}
        </p>
      )}
      {dir.data?.more ? (
        <p className="text-xs text-muted">
          There are more than {count(dir.data.entries.length)} here; these are
          the first by name.
        </p>
      ) : null}
    </div>
  );
}

/** All logs, the place, then each directory down to this one, each a way back to it. */
function Crumbs({ at, go }: { at: Place; go: (p: Place | null) => void }) {
  const rest =
    at.dir === at.root ? [] : at.dir.slice(at.root.length + 1).split("/");
  const steps = [
    { label: at.root, dir: at.root },
    ...rest.map((name, i) => ({
      label: name,
      dir: [at.root, ...rest.slice(0, i + 1)].join("/"),
    })),
  ];
  const step =
    "rounded px-1 py-0.5 hover:bg-fill hover:text-fg aria-[current=page]:font-medium aria-[current=page]:text-fg";
  return (
    <nav
      aria-label="Where"
      className="-mx-1 flex flex-wrap items-center gap-0.5 text-sm text-muted"
    >
      <button type="button" className={step} onClick={() => go(null)}>
        All logs
      </button>
      {steps.map((s, i) => (
        <span key={s.dir} className="flex min-w-0 items-center gap-0.5">
          <ChevronRightIcon className="shrink-0 text-faint" />
          <button
            type="button"
            className={`${step} font-mono break-all`}
            aria-current={i === steps.length - 1 ? "page" : undefined}
            onClick={() => go({ root: at.root, dir: s.dir })}
          >
            {s.label}
          </button>
        </span>
      ))}
    </nav>
  );
}

function Section({
  title,
  note,
  children,
}: {
  title: string;
  note?: string;
  children: ReactNode;
}) {
  return (
    <section className="flex flex-col gap-1">
      <h3 className="caps text-[0.625rem] text-muted">{title}</h3>
      {note ? <p className="text-xs text-muted">{note}</p> : null}
      {children}
    </section>
  );
}

function Rows({ children }: { children: ReactNode }) {
  return <ul className="-mx-2 flex flex-col">{children}</ul>;
}

function Row({
  icon,
  pressed = false,
  into = false,
  aside,
  onClick,
  children,
}: {
  icon: ReactNode;
  pressed?: boolean;
  /** Goes into a directory rather than choosing. */
  into?: boolean;
  aside?: ReactNode;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <li>
      <button
        type="button"
        aria-pressed={into ? undefined : pressed}
        onClick={onClick}
        className="flex w-full items-center gap-2 rounded-md px-2 py-2 text-left text-sm hover:bg-fill aria-pressed:font-medium"
      >
        <span className="shrink-0 text-muted">{icon}</span>
        <span className="min-w-0 flex-1 break-all">{children}</span>
        {aside ? (
          <span className="shrink-0 text-xs text-muted tabular-nums">
            {aside}
          </span>
        ) : null}
        {pressed ? <CheckIcon className="shrink-0 text-brand" /> : null}
        {into ? <ChevronRightIcon className="shrink-0 text-faint" /> : null}
      </button>
    </li>
  );
}
