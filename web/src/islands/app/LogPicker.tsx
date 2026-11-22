import {
  useEffect,
  useMemo,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { useQuery } from "@tanstack/react-query";

import { getLogFiles, getLogs, getLogsByPath } from "@app/api/actions";
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

  // Opening is a step in the browser's history, and so is each directory gone into: Back goes up
  // a directory, as it would through folders, and out of the dialog from the top, rather than off
  // the page the dialog is on. Closed any other way, it takes its steps back off, so Back after it
  // is what it was before.
  const show = () => {
    window.history.pushState({ [stepKey]: 1, place: null }, "");
    setOpen(true);
  };
  const close = () => {
    const taken = stepOf(window.history.state);
    if (taken) window.history.go(-taken);
    setOpen(false);
  };

  return (
    <>
      <button
        type="button"
        aria-label={`Lines from: ${value === PASTED ? "lines pasted here" : value}`}
        aria-haspopup="dialog"
        onClick={show}
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
      <Dialog open={open} onClose={close} title="Lines from" wide>
        <Browser
          value={value}
          readers={readers}
          choose={(v) => {
            close();
            if (v !== value) onChange(v);
          }}
          backedOut={() => setOpen(false)}
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

/** The key the picker's steps carry in the browser's history: how many steps in this one is. */
const stepKey = "f2bLogPicker";

const stepOf = (state: unknown): number =>
  typeof state === "object" && state !== null && stepKey in state
    ? Number((state as Record<string, unknown>)[stepKey]) || 0
    : 0;

function Browser({
  value,
  readers,
  choose,
  backedOut,
}: {
  value: string;
  readers: Map<string, string[]>;
  choose: (value: string) => void;
  /** Back went past the dialog's first step: it is closed, and its steps are gone already. */
  backedOut: () => void;
}) {
  const [find, setFind] = useState("");
  const [at, setAt] = useState<Place | null>(null);
  // Every move is a step, up a crumb as well as down a directory: Back is where you were.
  const go = (p: Place | null) => {
    window.history.pushState(
      { [stepKey]: stepOf(window.history.state) + 1, place: p },
      "",
    );
    setAt(p);
    setFind("");
  };
  // Back and Forward among the steps: each carries its place.
  useEffect(() => {
    const moved = () => {
      const state = window.history.state as { place?: Place | null } | null;
      if (!stepOf(state)) {
        backedOut();
        return;
      }
      setAt(state?.place ?? null);
      setFind("");
    };
    window.addEventListener("popstate", moved);
    return () => window.removeEventListener("popstate", moved);
  }, [backedOut]);
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
  // Every file among the logs, asked for once something is typed, and looked through as it is.
  const searching = f !== "" && !typed;
  const index = useQuery({
    queryKey: qk.logFiles,
    queryFn: getLogFiles,
    enabled: searching,
    staleTime: 30_000,
  });
  const listed = new Set(logs.map(([path]) => path));
  const files = searching
    ? (index.data?.files ?? []).filter(
        (e) => !listed.has(e.path) && e.path.toLowerCase().includes(f),
      )
    : [];

  const log = logs[0]?.[0];
  const file = files[0];
  const place = places[0];
  const enter = typed
    ? () => choose(typed)
    : log
      ? () => choose(log)
      : file
        ? () => choose(file.path)
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
      {searching ? (
        <Section title="Files">
          {index.isPending ? (
            <p className="text-sm text-muted">Looking…</p>
          ) : index.isError ? (
            <p className="text-sm text-accent">{messageOf(index.error)}</p>
          ) : files.length ? (
            <FileRows
              files={files}
              value={value}
              choose={choose}
              label={(e) => e.path}
            />
          ) : (
            <p className="text-sm text-muted">No file by that name.</p>
          )}
          {index.data?.more ? (
            <p className="text-xs text-muted">
              The search stopped short, at {count(index.data.files.length)}{" "}
              files; a directory, gone into, lists the rest.
            </p>
          ) : null}
        </Section>
      ) : null}
      {searching && !places.length ? null : (
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
      )}
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
  // Files in the directories under this one, found by what is typed.
  const index = useQuery({
    queryKey: qk.logFiles,
    queryFn: getLogFiles,
    enabled: f !== "",
    staleTime: 30_000,
  });
  const under = (e: LogEntry) => e.path.slice(at.dir.length + 1);
  const below = f
    ? (index.data?.files ?? []).filter(
        (e) =>
          e.path.startsWith(`${at.dir}/`) &&
          under(e).includes("/") &&
          under(e).toLowerCase().includes(f),
      )
    : [];
  const first = shown[0];
  const deeper = below[0];
  const enter = first
    ? open(first)
    : deeper
      ? () => choose(deeper.path)
      : undefined;

  return (
    <div className="flex flex-col gap-2">
      {search("Find in this directory and under it", enter)}
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
      {below.length ? (
        <Section title="Further down">
          <FileRows files={below} value={value} choose={choose} label={under} />
        </Section>
      ) : null}
    </div>
  );
}

/** How many files found are drawn: typing more of the name finds the rest. */
const foundMax = 100;

/** Files found, each to choose, with which jails read it, its size and its age. */
function FileRows({
  files,
  value,
  choose,
  label,
}: {
  files: LogEntry[];
  value: string;
  choose: (value: string) => void;
  label: (e: LogEntry) => string;
}) {
  return (
    <>
      <Rows>
        {files.slice(0, foundMax).map((e) => (
          <Row
            key={e.path}
            icon={<FileIcon />}
            pressed={e.path === value}
            onClick={() => choose(e.path)}
            aside={
              <>
                {e.jails.length ? `${e.jails.join(", ")} · ` : ""}
                {size(e.size)} ·{" "}
                <span title={dateTime(e.modified)}>{ago(e.modified)}</span>
              </>
            }
          >
            <span className="font-mono">{label(e)}</span>
          </Row>
        ))}
      </Rows>
      {files.length > foundMax ? (
        <p className="text-xs text-muted">
          And {count(files.length - foundMax)} more; type more of the name.
        </p>
      ) : null}
    </>
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
