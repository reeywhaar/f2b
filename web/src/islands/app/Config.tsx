import { useMemo, useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";

import { getFiles, getStock } from "@app/api/actions";
import { qk } from "@app/api/keys";
import type { File, Kind } from "@app/api/types";
import { Button } from "@app/components/Button";
import { Dialog } from "@app/components/Dialog";
import { DummyRows } from "@app/components/Dummy";
import { Field } from "@app/components/Field";
import { Frame } from "@app/components/Frame";
import { Panel } from "@app/components/Panel";
import { SearchField } from "@app/components/SearchField";
import { TextField } from "@app/components/TextField";
import { ago, size } from "@app/format";
import { Link } from "@app/islands/app/Link";
import { go, paths } from "@app/islands/app/route";

const lists: {
  kind: Exclude<Kind, "settings">;
  title: string;
  one: string;
  dir: string;
  about: string;
}[] = [
  {
    kind: "jails",
    title: "Jails",
    one: "jail",
    dir: "jail.d",
    about:
      "Which log to read, with which filter, and what to do past how many failures.",
  },
  {
    kind: "filters",
    title: "Filters",
    one: "filter",
    dir: "filter.d",
    about:
      "What a failure looks like in a log. A file named after a stock filter overrides it.",
  },
  {
    kind: "actions",
    title: "Actions",
    one: "action",
    dir: "action.d",
    about:
      "What a ban does. Most jails use a stock iptables action, and need none here.",
  },
];

/** The top-level files fail2ban reads after its own, which the engine passes through. */
const settings = [
  {
    name: "fail2ban.local",
    about:
      "fail2ban's own: its log level, and how long its database keeps bans.",
  },
  {
    name: "jail.local",
    about: "What every jail does unless it says otherwise, under [DEFAULT].",
  },
  {
    name: "paths-overrides.local",
    about: "Where the stock jails look for logs: sshd_log and the rest.",
  },
];

/** What is edited, by kind, and fail2ban's own files to read and override. */
export function Config() {
  const files = useQuery({ queryKey: qk.files, queryFn: getFiles });
  const [adding, setAdding] = useState<(typeof lists)[number] | null>(null);
  const all = files.data?.files ?? [];

  return (
    <Frame>
      <p className="max-w-3xl text-sm text-muted">
        These are the files in{" "}
        <code className="font-mono text-xs">/data/fail2ban</code>, laid over
        fail2ban&rsquo;s own configuration. A save is tried on fail2ban first
        and refused if fail2ban would refuse it; then fail2ban reloads.
      </p>
      {lists.map((l) => (
        <Panel
          key={l.kind}
          title={l.title}
          state={files}
          dummy={<DummyRows count={3} />}
        >
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-3">
              <p className="flex-1 text-sm text-muted">{l.about}</p>
              <Button size="bar" onClick={() => setAdding(l)}>
                New {l.one}…
              </Button>
            </div>
            <Files
              files={all.filter((f) => f.kind === l.kind)}
              kind={l.kind}
              dir={l.dir}
            />
          </div>
        </Panel>
      ))}
      <Panel title="Settings" state={files} dummy={<DummyRows count={3} />}>
        <ul className="flex flex-col divide-y divide-line rounded-lg border border-line bg-bg">
          {settings.map((s) => {
            const f = all.find(
              (x) => x.kind === "settings" && x.name === s.name,
            );
            return (
              <li key={s.name}>
                <Link
                  href={paths.file("settings", s.name, !f)}
                  className="flex flex-wrap items-baseline gap-x-4 gap-y-0.5 px-4 py-2.5 hover:bg-fill"
                >
                  <span className="font-mono text-sm">{s.name}</span>
                  <span className="flex-1 text-xs text-muted">{s.about}</span>
                  <span className="text-xs text-faint">
                    {f
                      ? `${size(f.size)}, changed ${ago(f.modified)}`
                      : "not made: create"}
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      </Panel>
      <StockList />
      <NewFile kind={adding} onClose={() => setAdding(null)} />
    </Frame>
  );
}

function Files({
  files,
  kind,
  dir,
}: {
  files: File[];
  kind: Kind;
  dir: string;
}) {
  if (files.length === 0) {
    return <p className="text-sm text-faint">Nothing in {dir} yet.</p>;
  }
  return (
    <ul className="flex flex-col divide-y divide-line rounded-lg border border-line bg-bg">
      {files.map((f) => (
        <li key={f.name}>
          <Link
            href={paths.file(kind, f.name)}
            className="flex flex-wrap items-baseline gap-x-4 gap-y-0.5 px-4 py-2.5 hover:bg-fill"
          >
            <span className="font-mono text-sm">{f.name}</span>
            {kind === "jails" && f.sections.length > 0 ? (
              <span className="text-xs text-muted">
                {f.sections.length === 1 ? "jail" : "jails"}{" "}
                {f.sections.join(", ")}
              </span>
            ) : null}
            <span className="flex-1" />
            <span className="text-xs text-faint">
              {size(f.size)}, changed {ago(f.modified)}
            </span>
          </Link>
        </li>
      ))}
    </ul>
  );
}

const fileName = /^[A-Za-z0-9][A-Za-z0-9_.@-]{0,95}$/;

/** A name as fail2ban reads it: .local unless it says .conf. */
const withExtension = (n: string) =>
  n.endsWith(".local") || n.endsWith(".conf") ? n : `${n}.local`;

/** A name, and then the editor, with what a new file of the kind starts with. */
function NewFile({
  kind,
  onClose,
}: {
  kind: (typeof lists)[number] | null;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!kind) return;
    const n = withExtension(name.trim());
    if (!fileName.test(n)) {
      setError(
        "Letters, digits, dots, dashes and underscores, starting with a letter or a digit.",
      );
      return;
    }
    setName("");
    setError("");
    onClose();
    go(paths.file(kind.kind, n, true));
  };
  return (
    <Dialog
      open={kind !== null}
      onClose={onClose}
      title={kind ? `New ${kind.one}` : ""}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="solid"
            type="submit"
            form="new-file"
            disabled={!name.trim()}
          >
            Open the editor
          </Button>
        </>
      }
    >
      <form id="new-file" onSubmit={submit}>
        <Field
          label="Name"
          hint={
            kind?.kind === "jails"
              ? "The file's name. The jail's own name is the section inside it, which the editor starts with this one."
              : "A jail names a filter or an action by this, without .local. Named after a stock one, it overrides that one's settings."
          }
        >
          <TextField
            data-autofocus
            className="w-full font-mono"
            placeholder={
              kind?.kind === "jails"
                ? "sshd"
                : kind?.kind === "filters"
                  ? "my-app"
                  : "notify"
            }
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoComplete="off"
          />
        </Field>
      </form>
      {kind ? (
        <p className="text-sm text-muted">
          It is saved as{" "}
          <code className="font-mono text-xs">
            {kind.dir}/{withExtension(name.trim() || "…")}
          </code>{" "}
          once fail2ban accepts it.
        </p>
      ) : null}
      {error ? <p className="text-sm text-accent">{error}</p> : null}
    </Dialog>
  );
}

/** fail2ban's own filters and actions, to read, and to start an override from. */
function StockList() {
  const stock = useQuery({ queryKey: qk.stock, queryFn: getStock });
  const [filter, setFilter] = useState("");
  const groups = useMemo(() => {
    const f = filter.trim().toLowerCase();
    const pick = (names: string[]) =>
      f ? names.filter((n) => n.toLowerCase().includes(f)) : names;
    const s = stock.data;
    return s
      ? [
          { title: "Filters", dir: "filter.d/", names: pick(s.filters) },
          { title: "Actions", dir: "action.d/", names: pick(s.actions) },
          { title: "Configuration", dir: "", names: pick(s.other) },
        ]
      : [];
  }, [stock.data, filter]);
  const total = groups.reduce((n, g) => n + g.names.length, 0);

  return (
    <Panel title="fail2ban's own" state={stock} dummy={<DummyRows count={2} />}>
      <div className="flex flex-col gap-3">
        <p className="text-sm text-muted">
          What the engine&rsquo;s fail2ban package came with, read-only. A jail
          names these by their name without{" "}
          <code className="font-mono text-xs">.conf</code>; override one from
          its page.
        </p>
        <SearchField
          placeholder="Find a filter or an action"
          aria-label="Find a stock filter or action"
          className="w-full sm:w-72"
          value={filter}
          onChange={setFilter}
        />
        {total === 0 ? (
          <p className="text-sm text-faint">
            {filter ? "Nothing by that name." : "The engine has none to show."}
          </p>
        ) : (
          groups
            .filter((g) => g.names.length > 0)
            .map((g) => (
              <details
                key={g.title}
                open={!!filter}
                className="rounded-lg border border-line bg-bg"
              >
                <summary className="cursor-pointer px-4 py-2 text-sm select-none hover:bg-fill">
                  {g.title} <span className="text-faint">{g.names.length}</span>
                </summary>
                <ul className="grid grid-cols-1 gap-x-4 border-t border-line px-4 py-2 sm:grid-cols-2 lg:grid-cols-3">
                  {g.names.map((n) => (
                    <li key={n}>
                      <Link
                        href={paths.stock(g.dir + n)}
                        className="font-mono text-xs leading-6 text-muted hover:text-fg hover:underline"
                      >
                        {n.replace(/\.conf$/, "")}
                      </Link>
                    </li>
                  ))}
                </ul>
              </details>
            ))
        )}
      </div>
    </Panel>
  );
}
