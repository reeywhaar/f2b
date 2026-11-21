import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";

import { getAuthMe, getEngine } from "@app/api/actions";
import { qk } from "@app/api/keys";
import { CogIcon } from "@app/components/icons/Icon";
import { Wordmark } from "@app/components/Wordmark";
import { Link } from "@app/islands/app/Link";
import { paths, type Route } from "@app/islands/app/route";
import { StateDot, stateWords } from "@app/islands/app/state";

const link =
  "inline-flex min-h-8 items-center gap-1.5 rounded-md px-2 text-sm whitespace-nowrap text-muted hover:bg-fill hover:text-fg aria-[current=page]:bg-fill aria-[current=page]:text-fg pointer-coarse:min-h-9";

const sections: { label: string; href: string; on: Route["page"][] }[] = [
  { label: "Overview", href: paths.overview(), on: ["overview"] },
  { label: "Bans", href: paths.bans, on: ["bans"] },
  { label: "History", href: paths.history(), on: ["history"] },
  { label: "Log", href: paths.log, on: ["log"] },
];

/** Where the configuration is: the label's link, not a section beside the others. */
const configPages: Route["page"][] = ["config", "file", "stock"];

/**
 * The bar across the top: the name; the sections, the log's carrying how fail2ban is doing; and
 * the way to this server's configuration, named as F2B_LABEL names the server.
 */
export function Header({ route }: { route: Route }) {
  const engine = useQuery({
    queryKey: qk.engine,
    queryFn: getEngine,
    refetchInterval: 5000,
  });
  const me = useQuery({
    queryKey: qk.me,
    queryFn: getAuthMe,
    staleTime: Infinity,
  });
  const label = me.data?.label ?? "";
  // The tab says which server too, for somebody with several open.
  useEffect(() => {
    document.title = label ? `${label} · f2b` : "f2b";
  }, [label]);
  const state = engine.data?.fail2ban;
  const health = engine.isError
    ? "The engine is not answering"
    : state
      ? stateWords(state)
      : "Asking the engine…";

  return (
    <header className="border-b border-line bg-bg">
      {/* On a phone the sections take a row of their own under the name, rather than
          scrolling out of sight beside it, pulled left by a link's padding so the first word
          lines up with the name above it. */}
      <div className="mx-auto flex w-full max-w-7xl flex-wrap items-center gap-x-2 gap-y-1 px-2 py-1.5 sm:flex-nowrap sm:px-4">
        <Link
          href={paths.overview()}
          className="mr-2 font-semibold whitespace-nowrap"
        >
          <Wordmark />
        </Link>
        <nav className="scroll-thin order-last -ml-2 flex w-[calc(100%+0.5rem)] min-w-0 gap-0.5 overflow-x-auto sm:order-none sm:ml-0 sm:w-auto sm:flex-1">
          {sections.map((s) => (
            <Link
              key={s.label}
              href={s.href}
              aria-current={s.on.includes(route.page) ? "page" : undefined}
              className={link}
              title={s.href === paths.log ? health : undefined}
            >
              {/* The log is where fail2ban's state is explained, so the state is shown on the
                  way to it rather than as a second way there. */}
              {s.href === paths.log ? (
                <>
                  <StateDot
                    state={engine.isError ? "unreachable" : state?.state}
                  />
                  <span className="sr-only">{health}: </span>
                </>
              ) : null}
              {s.label}
            </Link>
          ))}
        </nav>
        {/* This server's settings, under its name: a cog alone where there is no label, in the
            brand's color while they are open. */}
        <Link
          href={paths.config}
          aria-current={configPages.includes(route.page) ? "page" : undefined}
          title={
            label ? "Config of this server, as F2B_LABEL names it" : "Config"
          }
          className="group ml-auto inline-flex min-h-7 max-w-48 min-w-0 items-center gap-1.5 rounded-md bg-fill px-2 text-sm font-medium whitespace-nowrap hover:bg-control-hover pointer-coarse:min-h-9"
        >
          <CogIcon className="shrink-0 text-muted group-aria-[current=page]:text-brand" />
          {label ? <span className="truncate">{label}</span> : null}
          <span className="sr-only">{label ? ": Config" : "Config"}</span>
        </Link>
      </div>
    </header>
  );
}
