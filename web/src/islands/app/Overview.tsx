import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  getEngine,
  getJails,
  getStats,
  postEngineRestart,
} from "@app/api/actions";
import { qk } from "@app/api/keys";
import { messageOf } from "@app/api/transport";
import type { Jail } from "@app/api/types";
import { BansChart } from "@app/charts/BansChart";
import { jailColors } from "@app/charts/colors";
import { Button } from "@app/components/Button";
import { useConfirm } from "@app/components/Confirm";
import { DummyRows } from "@app/components/Dummy";
import { Frame } from "@app/components/Frame";
import { Panel } from "@app/components/Panel";
import { ago, count, span } from "@app/format";
import { Link } from "@app/islands/app/Link";
import { paths, ranges } from "@app/islands/app/route";
import { StateDot, stateWords } from "@app/islands/app/state";

/** How fail2ban is doing, what it has banned lately, and its jails. */
export function Overview({ days }: { days: number }) {
  const jails = useQuery({
    queryKey: qk.jails,
    queryFn: getJails,
    refetchInterval: 10000,
  });
  const stats = useQuery({
    queryKey: qk.stats(days),
    queryFn: () => getStats(days),
    refetchInterval: 30000,
  });
  const colors = useMemo(
    () =>
      jailColors([
        ...(jails.data?.jails.map((j) => j.name) ?? []),
        ...(stats.data?.jails ?? []),
      ]),
    [jails.data, stats.data],
  );
  const bannedNow = jails.data?.jails.reduce((n, j) => n + j.bannedNow, 0);

  return (
    <Frame>
      <Status />
      <section
        aria-label="Counts"
        className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5"
      >
        <Tile label="Banned now" value={bannedNow} href={paths.bans} />
        <Tile label="Bans, last 24 hours" value={stats.data?.lastDay} />
        <Tile
          label={`Bans, ${days} days`}
          value={stats.data?.bans}
          href={paths.history()}
        />
        <Tile label="Addresses banned" value={stats.data?.ips} />
        <Tile label="Banned more than once" value={stats.data?.repeat} />
      </section>

      <section>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <h2 className="text-sm font-semibold tracking-wide uppercase">
            Bans per day
          </h2>
          <span className="flex-1" />
          <div
            role="group"
            aria-label="Range"
            className="flex gap-0.5 rounded-md bg-control p-0.5"
          >
            {ranges.map((r) => (
              <Link
                key={r}
                href={paths.overview(r)}
                aria-current={r === days ? "page" : undefined}
                className="rounded px-2 py-0.5 text-xs text-muted hover:text-fg aria-[current=page]:bg-bg aria-[current=page]:text-fg aria-[current=page]:shadow-sm"
              >
                {r} days
              </Link>
            ))}
          </div>
        </div>
        <div className="rounded-lg border border-line bg-bg p-2 sm:p-3">
          {stats.isError ? (
            <p className="text-sm text-accent">{messageOf(stats.error)}</p>
          ) : stats.data ? (
            <BansChart stats={stats.data} colors={colors} />
          ) : (
            <div className="dummy h-[228px] rounded-md" />
          )}
        </div>
      </section>

      <Panel title="Jails" state={jails} dummy={<DummyRows count={4} />}>
        <Jails jails={jails.data?.jails ?? []} colors={colors} />
      </Panel>

      <Panel
        title={`Most banned, ${days} days`}
        state={stats}
        dummy={<DummyRows count={4} />}
      >
        {stats.data?.top.length ? (
          <div className="scroll-thin overflow-x-auto">
            <table className="w-full text-left text-sm tabular-nums">
              <thead className="text-xs text-muted">
                <tr>
                  <th className="py-1.5 pr-4 font-medium">Address</th>
                  <th className="py-1.5 pr-4 text-right font-medium">Bans</th>
                  <th className="py-1.5 pr-4 font-medium">Jails</th>
                  <th className="py-1.5 font-medium">Last</th>
                </tr>
              </thead>
              <tbody>
                {stats.data.top.map((o) => (
                  <tr key={o.ip} className="border-t border-line">
                    <td className="py-1.5 pr-4 font-mono text-xs">
                      <Link
                        href={paths.history({ ip: o.ip })}
                        className="hover:underline"
                      >
                        {o.ip}
                      </Link>
                    </td>
                    <td className="py-1.5 pr-4 text-right">{count(o.bans)}</td>
                    <td className="py-1.5 pr-4 text-muted">
                      {o.jails.join(", ")}
                    </td>
                    <td className="py-1.5 whitespace-nowrap text-muted">
                      {ago(o.last)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-muted">
            Nobody was banned in these {days} days.
          </p>
        )}
      </Panel>
    </Frame>
  );
}

function Tile({
  label,
  value,
  href,
}: {
  label: string;
  value: number | undefined;
  href?: string;
}) {
  const body = (
    <>
      <span className="caps text-xs text-muted">{label}</span>
      <span className="text-2xl font-semibold tabular-nums">
        {value === undefined ? (
          <span className="dummy inline-block h-7 w-12 rounded" />
        ) : (
          count(value)
        )}
      </span>
    </>
  );
  const look =
    "flex flex-col gap-1 rounded-lg border border-line bg-bg px-2 py-3 sm:px-4";
  return href ? (
    <Link href={href} className={`${look} hover:border-axis`}>
      {body}
    </Link>
  ) : (
    <div className={look}>{body}</div>
  );
}

/** fail2ban's state, and a way to restart it. */
function Status() {
  const engine = useQuery({
    queryKey: qk.engine,
    queryFn: getEngine,
    refetchInterval: 5000,
  });
  const client = useQueryClient();
  const confirm = useConfirm();
  const [error, setError] = useState("");
  const restart = useMutation({
    mutationFn: postEngineRestart,
    onSuccess: () => client.invalidateQueries(),
    onError: (err) => setError(messageOf(err)),
  });
  const s = engine.data?.fail2ban;

  return (
    <section className="flex flex-wrap items-center gap-3 rounded-lg border border-line bg-bg px-2 py-3 sm:px-4">
      <StateDot state={engine.isError ? "unreachable" : s?.state} />
      <div className="flex min-w-0 flex-1 flex-col">
        <p className="text-sm font-medium">
          {engine.isError
            ? "The engine is not answering"
            : s
              ? stateWords(s)
              : "Asking the engine…"}
        </p>
        {engine.isError ? (
          <p className="text-xs text-muted">{messageOf(engine.error)}</p>
        ) : s && s.state !== "running" ? (
          <p className="text-xs text-muted">
            The{" "}
            <Link href={paths.log} className="underline">
              log
            </Link>{" "}
            says why.
          </p>
        ) : s && s.restarts > 0 ? (
          <p className="text-xs text-muted">
            It has stopped on its own {s.restarts}{" "}
            {s.restarts === 1 ? "time" : "times"} since the engine started.
          </p>
        ) : null}
        {error ? <p className="text-xs text-accent">{error}</p> : null}
      </div>
      <Button
        size="bar"
        disabled={!s || restart.isPending}
        onClick={async () => {
          setError("");
          if (
            await confirm({
              title: "Restart fail2ban",
              message:
                "fail2ban stops, which takes its rules out of the firewall, and starts again with the configuration on disk. Bans still in force are put back from its database.",
              confirm: "Restart",
            })
          ) {
            restart.mutate();
          }
        }}
      >
        Restart…
      </Button>
    </section>
  );
}

function Jails({
  jails,
  colors,
}: {
  jails: Jail[];
  colors: Map<string, string>;
}) {
  if (jails.length === 0) {
    return (
      <p className="text-sm text-muted">
        No jail is running.{" "}
        <Link href={paths.config} className="underline">
          Add one under Config.
        </Link>
      </p>
    );
  }
  return (
    <>
      {/* A card a jail on a phone: six columns do not fit, and a log's path squeezed into the
          last of them broke a letter a line. */}
      <ul className="flex flex-col divide-y divide-line rounded-lg border border-line bg-bg sm:hidden">
        {jails.map((j) => (
          <li key={j.name} className="flex flex-col gap-1 px-2 py-2.5 sm:px-4">
            <div className="flex items-center gap-2">
              <span
                aria-hidden="true"
                className="size-2.5 shrink-0 rounded-sm"
                style={{ background: colors.get(j.name) }}
              />
              {j.file ? (
                <Link
                  href={paths.file(j.file.kind, j.file.name)}
                  className="font-medium hover:underline"
                >
                  {j.name}
                </Link>
              ) : (
                <span className="font-medium">{j.name}</span>
              )}
              <span className="flex-1" />
              <span className="text-sm tabular-nums">
                {count(j.bannedNow)}
                <span className="text-faint">
                  {" "}
                  / {count(j.bannedTotal)} banned
                </span>
              </span>
            </div>
            <p className="text-xs text-muted tabular-nums">
              {count(j.failedNow)} / {count(j.failedTotal)} failing · bans after{" "}
              {j.maxRetry} in {span(j.findTime)}, for {span(j.banTime)}
            </p>
            <p className="font-mono text-[11px] break-all text-muted">
              {j.logs.join(" ")}
            </p>
          </li>
        ))}
      </ul>
      <div className="scroll-thin hidden overflow-x-auto sm:block">
        <table className="w-full text-left text-sm tabular-nums">
          <thead className="text-xs text-muted">
            <tr>
              <th className="py-1.5 pr-4 font-medium">Jail</th>
              <th className="py-1.5 pr-4 text-right font-medium">Banned</th>
              <th className="py-1.5 pr-4 text-right font-medium">Failing</th>
              <th className="py-1.5 pr-4 font-medium whitespace-nowrap">
                Bans after
              </th>
              <th className="py-1.5 pr-4 font-medium">For</th>
              <th className="py-1.5 font-medium">Reads</th>
            </tr>
          </thead>
          <tbody>
            {jails.map((j) => (
              <tr key={j.name} className="border-t border-line align-top">
                <td className="py-2 pr-4">
                  <span className="flex items-center gap-2 font-medium">
                    <span
                      aria-hidden="true"
                      className="size-2.5 shrink-0 rounded-sm"
                      style={{ background: colors.get(j.name) }}
                    />
                    {j.file ? (
                      <Link
                        href={paths.file(j.file.kind, j.file.name)}
                        className="hover:underline"
                      >
                        {j.name}
                      </Link>
                    ) : (
                      j.name
                    )}
                  </span>
                </td>
                <td className="py-2 pr-4 text-right">
                  <span title="Now">{count(j.bannedNow)}</span>
                  <span className="text-faint" title="Since fail2ban started">
                    {" "}
                    / {count(j.bannedTotal)}
                  </span>
                </td>
                <td className="py-2 pr-4 text-right">
                  <span title="Now">{count(j.failedNow)}</span>
                  <span className="text-faint" title="Since fail2ban started">
                    {" "}
                    / {count(j.failedTotal)}
                  </span>
                </td>
                <td className="py-2 pr-4 whitespace-nowrap text-muted">
                  {j.maxRetry} in {span(j.findTime)}
                </td>
                <td className="py-2 pr-4 whitespace-nowrap text-muted">
                  {span(j.banTime)}
                </td>
                <td className="py-2 font-mono text-xs break-all text-muted">
                  {j.logs.join(" ")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-xs text-faint">
        Banned and failing: now / since fail2ban started.
      </p>
    </>
  );
}
