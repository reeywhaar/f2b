import { useMemo, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { deleteBansByIp, getBans, getJails, postBans } from "@app/api/actions";
import { qk } from "@app/api/keys";
import { messageOf } from "@app/api/transport";
import type { CurrentBan } from "@app/api/types";
import { Button } from "@app/components/Button";
import { useConfirm } from "@app/components/Confirm";
import { Dialog } from "@app/components/Dialog";
import { DummyRows } from "@app/components/Dummy";
import { Field, Fields, Group } from "@app/components/Field";
import { Frame } from "@app/components/Frame";
import { Panel } from "@app/components/Panel";
import { Picker } from "@app/components/Picker";
import { SearchField } from "@app/components/SearchField";
import { TextField } from "@app/components/TextField";
import { ago, dateTime, span, until } from "@app/format";
import { Link } from "@app/islands/app/Link";
import { paths } from "@app/islands/app/route";

/** Every ban in force, a way to lift each, and a way to add one. */
export function Bans() {
  const bans = useQuery({
    queryKey: qk.bans,
    queryFn: getBans,
    refetchInterval: 10000,
  });
  const [filter, setFilter] = useState("");
  const [adding, setAdding] = useState(false);
  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase();
    const all = bans.data?.bans ?? [];
    return f
      ? all.filter((b) => b.ip.includes(f) || b.jail.toLowerCase().includes(f))
      : all;
  }, [bans.data, filter]);

  return (
    <Frame>
      <div className="flex justify-end">
        <Button variant="solid" size="bar" onClick={() => setAdding(true)}>
          Ban an address…
        </Button>
      </div>
      <Panel
        title={
          bans.data ? `Banned now · ${bans.data.bans.length}` : "Banned now"
        }
        // Only once there is a list to narrow.
        filter={
          bans.data?.bans.length ? (
            <SearchField
              placeholder="Address or jail"
              aria-label="Show only bans of an address or a jail"
              size="bar"
              className="w-full sm:w-72"
              value={filter}
              onChange={setFilter}
            />
          ) : null
        }
        state={bans}
        dummy={<DummyRows count={6} />}
      >
        {shown.length === 0 ? (
          <p className="text-sm text-muted">
            {filter
              ? "No ban in force matches that."
              : "Nobody is banned right now."}
          </p>
        ) : (
          <ul className="flex flex-col divide-y divide-line rounded-lg border border-line bg-bg">
            {shown.map((b) => (
              <Row key={`${b.jail}/${b.ip}`} ban={b} />
            ))}
          </ul>
        )}
      </Panel>
      <BanDialog open={adding} onClose={() => setAdding(false)} />
    </Frame>
  );
}

function Row({ ban }: { ban: CurrentBan }) {
  const client = useQueryClient();
  const confirm = useConfirm();
  const [error, setError] = useState("");
  const unban = useMutation({
    mutationFn: () => deleteBansByIp(ban.ip, ban.jail),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: qk.bans });
      client.invalidateQueries({ queryKey: qk.jails });
      client.invalidateQueries({ queryKey: qk.history });
    },
    onError: (err) => setError(messageOf(err)),
  });

  return (
    // Unban in a column of its own, so a long address wraps beside it rather than pushing it
    // onto a line of its own.
    <li className="flex items-start gap-3 px-2 py-3 sm:px-4">
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <Link
            href={paths.history({ ip: ban.ip })}
            className="font-mono text-sm font-medium hover:underline"
          >
            {ban.ip}
          </Link>
          <span className="rounded bg-fill px-1.5 py-0.5 text-xs">
            {ban.jail}
          </span>
          {ban.count > 1 ? (
            <span className="hidden text-xs text-warn sm:inline">
              {ordinal(ban.count)} ban here
            </span>
          ) : null}
          <span className="flex-1" />
          {/* On a phone, a line of its own under the address, so Unban stays beside what it
              unbans. */}
          <span className="order-last w-full text-xs text-muted tabular-nums sm:order-none sm:w-auto sm:whitespace-nowrap">
            {ban.count > 1 ? (
              <span className="text-warn sm:hidden">
                {ordinal(ban.count)} ban here ·{" "}
              </span>
            ) : null}
            {ban.at ? (
              <span title={dateTime(ban.at)}>banned {ago(ban.at)}</span>
            ) : (
              "when is not recorded"
            )}
            {ban.duration < 0
              ? ", for good"
              : ban.until
                ? `, lifted ${until(ban.until)}`
                : ban.duration
                  ? `, for ${span(ban.duration)}`
                  : ""}
          </span>
        </div>
        {ban.matches.length > 0 ? (
          <details className="text-xs">
            <summary className="cursor-pointer text-muted select-none hover:text-fg">
              {ban.failures || ban.matches.length}{" "}
              {ban.failures === 1 ? "failure" : "failures"}: the lines
            </summary>
            <pre className="scroll-thin mt-1 overflow-x-auto rounded-md bg-(--color-code-bg) p-2 font-mono text-[11px] leading-relaxed text-muted">
              {ban.matches.join("\n")}
            </pre>
          </details>
        ) : null}
        {error ? <p className="text-xs text-accent">{error}</p> : null}
      </div>
      <Button
        size="bar"
        className="shrink-0"
        variant="danger"
        disabled={unban.isPending}
        onClick={async () => {
          setError("");
          if (
            await confirm({
              title: `Unban ${ban.ip}`,
              message: (
                <>
                  {ban.ip} is let back past the {ban.jail} jail at once.
                  fail2ban also forgets its earlier bans of this address in this
                  jail, so they leave the history: that is fail2ban's own doing,
                  not f2b's.
                </>
              ),
              confirm: "Unban",
              danger: true,
            })
          ) {
            unban.mutate();
          }
        }}
      >
        Unban…
      </Button>
    </li>
  );
}

function ordinal(n: number): string {
  const s = ["th", "st", "nd", "rd"];
  const v = n % 100;
  return n + (s[(v - 20) % 10] ?? s[v] ?? s[0]!);
}

/** Banning by hand: an address, or a range, in one of the running jails. */
function BanDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const jails = useQuery({
    queryKey: qk.jails,
    queryFn: getJails,
    enabled: open,
  });
  const client = useQueryClient();
  const [jail, setJail] = useState("");
  const [ip, setIp] = useState("");
  const [error, setError] = useState("");
  const ban = useMutation({
    mutationFn: () =>
      postBans({
        jail: jail || jails.data?.jails[0]?.name || "",
        ip: ip.trim(),
      }),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: qk.bans });
      client.invalidateQueries({ queryKey: qk.jails });
      client.invalidateQueries({ queryKey: qk.history });
      setIp("");
      onClose();
    },
    onError: (err) => setError(messageOf(err)),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setError("");
    ban.mutate();
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Ban an address"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="solid"
            type="submit"
            form="ban"
            disabled={ban.isPending || !ip.trim()}
          >
            Ban
          </Button>
        </>
      }
    >
      <form id="ban" onSubmit={submit}>
        <Fields>
          <Field
            label="Address"
            hint="An IPv4 or IPv6 address, or a range of them: 203.0.113.0/24."
          >
            <TextField
              data-autofocus
              className="w-full font-mono"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="203.0.113.7"
              autoComplete="off"
            />
          </Field>
          {/* A group, not a label: the picker's own dialog is inside it, and a click there would
              otherwise be taken as a click on the picker. */}
          <Group
            label="Jail"
            hint="The ban is the jail's: its action does the blocking, and it lasts the jail's ban time."
          >
            <Picker
              label="Jail"
              className="w-full"
              value={jail || jails.data?.jails[0]?.name || ""}
              options={(jails.data?.jails ?? []).map((j) => ({
                value: j.name,
                label: j.name,
              }))}
              onChange={setJail}
            />
          </Group>
        </Fields>
      </form>
      {error ? <p className="text-sm text-accent">{error}</p> : null}
    </Dialog>
  );
}
