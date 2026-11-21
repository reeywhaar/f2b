import { useEffect, useRef, useState } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";

import { getHistory, getJails, getStats } from "@app/api/actions";
import { qk } from "@app/api/keys";
import type { Ban } from "@app/api/types";
import { Button } from "@app/components/Button";
import { DummyRows } from "@app/components/Dummy";
import { Frame } from "@app/components/Frame";
import { Panel } from "@app/components/Panel";
import { Picker } from "@app/components/Picker";
import { SearchField } from "@app/components/SearchField";
import { useDebounced } from "@app/debounce";
import { dateTime, span } from "@app/format";
import { go, paths } from "@app/islands/app/route";

/**
 * Every ban fail2ban's database still holds, newest first: for its purge age, ninety days unless
 * fail2ban.local says otherwise.
 */
export function History({ jail, ip }: { jail: string; ip: string }) {
  const [typed, setTyped] = useState(ip);
  useEffect(() => setTyped(ip), [ip]);
  const jails = useQuery({ queryKey: qk.jails, queryFn: getJails });
  const known = useQuery({
    queryKey: qk.stats(90),
    queryFn: () => getStats(90),
  });
  const names = [
    ...new Set([
      ...(jails.data?.jails.map((j) => j.name) ?? []),
      ...(known.data?.jails ?? []),
    ]),
  ].toSorted();

  const history = useInfiniteQuery({
    queryKey: qk.historyPage(jail, ip),
    queryFn: ({ pageParam }) =>
      getHistory({ jail, ip, before: pageParam, limit: 50 }),
    initialPageParam: 0,
    getNextPageParam: (last) => (last.next ? last.next : undefined),
  });
  const bans = history.data?.pages.flatMap((p) => p.bans) ?? [];

  // The address applies itself once typing pauses. The route is read through a ref, so a click
  // on an address in the list, which moves the route first, is not undone by the pause catching
  // up with what was typed before it.
  const route = useRef({ jail, ip });
  route.current = { jail, ip };
  const show = (address: string) => {
    if (address !== route.current.ip) {
      go(paths.history({ jail: route.current.jail, ip: address }), true);
    }
  };
  const settled = useDebounced(typed.trim(), 400);
  useEffect(() => show(settled), [settled]);

  return (
    <Frame>
      <Panel
        title="Bans"
        filter={
          <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
            <SearchField
              placeholder="An address"
              aria-label="Only the bans of this address"
              size="bar"
              className="w-full sm:w-72"
              inputClassName="font-mono placeholder:font-sans"
              value={typed}
              onChange={(v) => {
                setTyped(v);
                // Emptied is shown at once: there is nothing more coming.
                if (v === "") show("");
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") show(typed.trim());
              }}
            />
            <Picker
              label="Jail"
              size="bar"
              className="w-full sm:w-56"
              value={jail}
              options={[
                { value: "", label: "Every jail" },
                ...names.map((n) => ({ value: n, label: n })),
              ]}
              onChange={(v) => go(paths.history({ jail: v, ip }), true)}
            />
          </div>
        }
        state={history}
        dummy={<DummyRows count={8} />}
      >
        {bans.length === 0 ? (
          <p className="text-sm text-muted">
            {jail || ip
              ? "fail2ban's database holds no ban like that."
              : "fail2ban's database holds no bans yet."}
          </p>
        ) : (
          <div className="flex flex-col gap-3">
            <ul className="flex flex-col divide-y divide-line rounded-lg border border-line bg-bg">
              {bans.map((b) => (
                <li key={b.id} className="flex flex-col gap-1 px-4 py-2.5">
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
                    {/* A column to read down on a wide screen. On a phone, when and for how
                        long make a line of their own under the address, every row alike. */}
                    <span className="order-last w-full text-xs text-muted tabular-nums sm:order-none sm:w-40 sm:shrink-0">
                      {dateTime(b.at)}
                      <span className="sm:hidden"> · {lasted(b)}</span>
                    </span>
                    <button
                      type="button"
                      className="font-mono text-sm hover:underline"
                      onClick={() =>
                        go(paths.history({ jail, ip: b.ip }), true)
                      }
                    >
                      {b.ip}
                    </button>
                    <button
                      type="button"
                      className="rounded bg-fill px-1.5 py-0.5 text-xs hover:bg-control-hover"
                      onClick={() =>
                        go(paths.history({ jail: b.jail, ip }), true)
                      }
                    >
                      {b.jail}
                    </button>
                    <span className="flex-1" />
                    <span className="hidden text-xs text-muted tabular-nums sm:inline">
                      {lasted(b)}
                    </span>
                  </div>
                  {b.matches.length > 0 ? (
                    <details className="text-xs">
                      <summary className="cursor-pointer text-muted select-none hover:text-fg">
                        {b.failures || b.matches.length}{" "}
                        {b.failures === 1 ? "failure" : "failures"}
                      </summary>
                      <pre className="scroll-thin mt-1 overflow-x-auto rounded-md bg-(--color-code-bg) p-2 font-mono text-[11px] leading-relaxed text-muted">
                        {b.matches.join("\n")}
                      </pre>
                    </details>
                  ) : null}
                </li>
              ))}
            </ul>
            {history.hasNextPage ? (
              <Button
                size="bar"
                className="self-center"
                disabled={history.isFetchingNextPage}
                onClick={() => history.fetchNextPage()}
              >
                {history.isFetchingNextPage ? "Reading…" : "Older bans"}
              </Button>
            ) : null}
          </div>
        )}
      </Panel>
    </Frame>
  );
}

/** How long a ban was for, and which of this address's bans in this jail it was. */
function lasted(b: Ban): string {
  const length = b.duration < 0 ? "for good" : `for ${span(b.duration)}`;
  return b.count > 1 ? `${length} · ban ${b.count} here` : length;
}
