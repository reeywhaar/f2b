import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  deleteAuthTokensById,
  getAuthTokens,
  postAuthTokens,
} from "@app/api/actions";
import { qk } from "@app/api/keys";
import { messageOf } from "@app/api/transport";
import type { Lifetime, Scope, Token } from "@app/api/types";
import { Button } from "@app/components/Button";
import { useConfirm } from "@app/components/Confirm";
import { CopyButton } from "@app/components/CopyButton";
import { Dialog } from "@app/components/Dialog";
import { DummyRows } from "@app/components/Dummy";
import { Field, Fields } from "@app/components/Field";
import { Panel } from "@app/components/Panel";
import { Select } from "@app/components/Select";
import { TextField } from "@app/components/TextField";
import { ago, dateTime, span, until } from "@app/format";

const day = 86400;

const lifetimes: { value: Lifetime; label: string; seconds: number }[] = [
  { value: "1d", label: "1 day", seconds: day },
  { value: "1w", label: "1 week", seconds: 7 * day },
  { value: "30d", label: "30 days", seconds: 30 * day },
  { value: "90d", label: "90 days", seconds: 90 * day },
  { value: "180d", label: "180 days", seconds: 180 * day },
  { value: "1y", label: "1 year", seconds: 365 * day },
  { value: "never", label: "Never", seconds: 0 },
];

/** A lifetime in the words it was chosen in: "90 days", not "12w 6d". */
function named(seconds: number): string {
  const l = lifetimes.find((x) => x.seconds === seconds);
  return l ? l.label.toLowerCase() : span(seconds);
}

const scopes: { value: Scope; label: string }[] = [
  { value: "read", label: "Read" },
  { value: "write", label: "Read and write" },
];

/** How long it lasts, in a few words: "90 days, and 30 days unused", "until revoked". */
function lasts(t: Token): string {
  const parts: string[] = [];
  if (t.expires) parts.push(named(t.expires - t.created));
  if (t.idle) parts.push(`${named(t.idle)} unused`);
  return parts.length ? parts.join(", and ") : "until revoked";
}

/**
 * API tokens, for scripts and agents: what reaches /api/v1 instead of the password. Made,
 * listed and revoked here, beside signing in, and shown once.
 */
export function Tokens() {
  const tokens = useQuery({ queryKey: qk.tokens, queryFn: getAuthTokens });
  const [creating, setCreating] = useState(false);
  const [made, setMade] = useState<{ token: Token; secret: string } | null>(
    null,
  );
  const list = tokens.data?.tokens ?? [];

  return (
    <Panel title="API tokens" state={tokens} dummy={<DummyRows count={2} />}>
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <p className="max-w-3xl flex-1 text-sm text-muted">
            For scripts and agents. A token reaches{" "}
            <code className="font-mono text-xs">/api/v1</code>, this engine in
            JSON:API, described at{" "}
            <a
              href="/api/v1/openapi.json"
              target="_blank"
              rel="noreferrer"
              className="font-mono text-xs underline-offset-2 hover:text-fg hover:underline"
            >
              /api/v1/openapi.json
            </a>
            . One that reads inspects everything and changes nothing; one that
            reads and writes can also ban, edit and restart.
          </p>
          <Button onClick={() => setCreating(true)}>New token…</Button>
        </div>
        {list.length ? (
          <ul className="flex flex-col divide-y divide-line rounded-lg border border-line bg-bg">
            {list.map((t) => (
              <TokenRow key={t.id} token={t} />
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted">No tokens.</p>
        )}
      </div>
      <NewTokenDialog
        open={creating}
        onClose={() => setCreating(false)}
        onMade={(m) => {
          setCreating(false);
          setMade(m);
        }}
      />
      <SecretDialog made={made} onClose={() => setMade(null)} />
    </Panel>
  );
}

function TokenRow({ token: t }: { token: Token }) {
  const confirm = useConfirm();
  const client = useQueryClient();
  const [error, setError] = useState("");
  const revoke = useMutation({
    mutationFn: () => deleteAuthTokensById(t.id),
    onSuccess: () => client.invalidateQueries({ queryKey: qk.tokens }),
    onError: (err) => setError(messageOf(err)),
  });
  const ask = async () => {
    setError("");
    if (
      await confirm({
        title: `Revoke ${t.name}`,
        message:
          "Whatever uses this token is refused from now on. A revoked token cannot be brought back; issue a new one instead.",
        confirm: "Revoke",
        danger: true,
      })
    ) {
      revoke.mutate();
    }
  };

  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1 px-(--h-padding) py-2.5">
      <div className="flex min-w-0 flex-1 flex-col gap-0.5">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="text-sm font-medium break-all">{t.name}</span>
          <span className="rounded bg-fill px-1.5 py-0.5 text-xs">
            {t.scope === "write" ? "reads and writes" : "reads"}
          </span>
          {t.expired ? (
            <span className="text-xs text-warn">expired</span>
          ) : null}
        </div>
        <p className="text-xs text-muted tabular-nums">
          <span title={dateTime(t.created)}>made {ago(t.created)}</span>
          {" · "}
          {t.lastUsed ? (
            <span title={dateTime(t.lastUsed)}>used {ago(t.lastUsed)}</span>
          ) : (
            "never used"
          )}
          {" · lasts "}
          {lasts(t)}
          {!t.expired && t.ends ? (
            <span title={dateTime(t.ends)}>, ends {until(t.ends)}</span>
          ) : null}
        </p>
        {error ? <p className="text-sm text-accent">{error}</p> : null}
      </div>
      <Button variant="danger" onClick={ask} disabled={revoke.isPending}>
        Revoke…
      </Button>
    </li>
  );
}

function NewTokenDialog({
  open,
  onClose,
  onMade,
}: {
  open: boolean;
  onClose: () => void;
  onMade: (made: { token: Token; secret: string }) => void;
}) {
  const client = useQueryClient();
  const [name, setName] = useState("");
  const [scope, setScope] = useState<Scope>("read");
  const [expiresIn, setExpiresIn] = useState<Lifetime>("90d");
  const [idleFor, setIdleFor] = useState<Lifetime>("30d");
  const [error, setError] = useState("");
  const issue = useMutation({
    mutationFn: () =>
      postAuthTokens({ name: name.trim(), scope, expiresIn, idleFor }),
    onSuccess: (made) => {
      client.invalidateQueries({ queryKey: qk.tokens });
      setName("");
      onMade(made);
    },
    onError: (err) => setError(messageOf(err)),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setError("");
    issue.mutate();
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="New API token"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="solid"
            type="submit"
            form="token"
            disabled={issue.isPending || !name.trim()}
          >
            Issue
          </Button>
        </>
      }
    >
      <form id="token" onSubmit={submit}>
        <Fields>
          <Field
            label="Name"
            hint="Who uses it: the log names each request a token makes by this."
          >
            <TextField
              data-autofocus
              className="w-full"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="claude on laptop"
              autoComplete="off"
              maxLength={60}
            />
          </Field>
          <Field
            label="Can"
            hint="Read takes every GET, the filter tester and the config check. Read and write also bans, unbans, saves files and restarts fail2ban."
          >
            <Select
              className="w-full"
              value={scope}
              onChange={(e) => setScope(e.target.value as Scope)}
            >
              {scopes.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field
            label="Expires after"
            hint="It stops working this long after it is issued, however it is used."
          >
            <Select
              className="w-full"
              value={expiresIn}
              onChange={(e) => setExpiresIn(e.target.value as Lifetime)}
            >
              {lifetimes.map((l) => (
                <option key={l.value} value={l.value}>
                  {l.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field
            label="Expires after no use"
            hint="It stops working when it has gone this long unused, so a token nothing uses any more ends by itself."
          >
            <Select
              className="w-full"
              value={idleFor}
              onChange={(e) => setIdleFor(e.target.value as Lifetime)}
            >
              {lifetimes.map((l) => (
                <option key={l.value} value={l.value}>
                  {l.label}
                </option>
              ))}
            </Select>
          </Field>
        </Fields>
      </form>
      {error ? <p className="text-sm text-accent">{error}</p> : null}
    </Dialog>
  );
}

/** The token, this once: f2b keeps a digest of it and cannot show it again. */
function SecretDialog({
  made,
  onClose,
}: {
  made: { token: Token; secret: string } | null;
  onClose: () => void;
}) {
  const example = made
    ? `curl -H "Authorization: Bearer ${made.secret}" ${window.location.origin}/api/v1/jails`
    : "";
  return (
    <Dialog
      open={made !== null}
      onClose={onClose}
      title={made ? `Token for ${made.token.name}` : ""}
      footer={
        <Button variant="solid" onClick={onClose}>
          Done
        </Button>
      }
    >
      {made ? (
        <div className="flex flex-col gap-3 text-sm">
          <p>
            Copy it now: this is the only time it is shown. f2b keeps a digest
            of it, which cannot be turned back into the token.
          </p>
          <div className="flex items-start gap-2 rounded-md bg-(--color-code-bg) p-2">
            <code className="min-w-0 flex-1 font-mono text-xs break-all select-all">
              {made.secret}
            </code>
            <CopyButton text={made.secret} label="the token" />
          </div>
          <p className="text-muted">Try it:</p>
          <div className="flex items-start gap-2 rounded-md bg-(--color-code-bg) p-2">
            <code className="min-w-0 flex-1 font-mono text-[11px] break-all text-muted">
              {example}
            </code>
            <CopyButton text={example} label="the example" />
          </div>
        </div>
      ) : null}
    </Dialog>
  );
}
