import type { DaemonState } from "@app/api/types";
import { ago, span } from "@app/format";

/** fail2ban's state as a dot: green running, amber starting, red stopped or unreachable. */
export function StateDot({
  state,
}: {
  state: DaemonState["state"] | "unreachable" | undefined;
}) {
  const color =
    state === "running"
      ? "bg-good"
      : state === "starting"
        ? "bg-warn animate-pulse"
        : state
          ? "bg-accent"
          : "bg-faint";
  return (
    <span
      aria-hidden="true"
      className={`size-2 shrink-0 rounded-full ${color}`}
    />
  );
}

/** fail2ban's state in a sentence. */
export function stateWords(s: DaemonState): string {
  const now = Date.now() / 1000;
  switch (s.state) {
    case "running":
      return `fail2ban ${s.version} running for ${span(now - s.since).split(" ")[0]}`;
    case "starting":
      return `fail2ban starting, since ${ago(s.since)}`;
    case "stopped":
      return `fail2ban stopped ${ago(s.since)}${s.lastExit ? `: ${s.lastExit}` : ""}`;
  }
}
