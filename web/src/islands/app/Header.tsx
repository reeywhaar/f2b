import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import {
  getEngine,
  postAuthLogout,
  postAuthLogoutEverywhere,
} from "@app/api/actions";
import { qk } from "@app/api/keys";
import { messageOf } from "@app/api/transport";
import { Button } from "@app/components/Button";
import { useConfirm } from "@app/components/Confirm";
import { Dialog } from "@app/components/Dialog";
import { Wordmark } from "@app/components/Wordmark";
import { leaveFor } from "@app/leave";
import { Link } from "@app/islands/app/Link";
import { paths, type Route } from "@app/islands/app/route";
import { StateDot, stateWords } from "@app/islands/app/state";

const link =
  "inline-flex min-h-8 items-center gap-1.5 rounded-md px-2 text-sm whitespace-nowrap text-muted hover:bg-fill hover:text-fg aria-[current=page]:bg-fill aria-[current=page]:text-fg pointer-coarse:min-h-9";

const sections: { label: string; href: string; on: Route["page"][] }[] = [
  { label: "Overview", href: paths.overview(), on: ["overview"] },
  { label: "Bans", href: paths.bans, on: ["bans"] },
  { label: "History", href: paths.history(), on: ["history"] },
  { label: "Config", href: paths.config, on: ["config", "file", "stock"] },
  { label: "Log", href: paths.log, on: ["log"] },
];

/** The bar across the top: the name, and the sections, the log's carrying how fail2ban is doing. */
export function Header({ route }: { route: Route }) {
  const engine = useQuery({
    queryKey: qk.engine,
    queryFn: getEngine,
    refetchInterval: 5000,
  });
  const [account, setAccount] = useState(false);
  const state = engine.data?.fail2ban;
  const health = engine.isError
    ? "The engine is not answering"
    : state
      ? stateWords(state)
      : "Asking the engine…";

  return (
    <header className="border-b border-line bg-bg">
      {/* On a phone the sections take a row of their own under the name, rather than
          scrolling out of sight beside it. */}
      <div className="mx-auto flex w-full max-w-7xl flex-wrap items-center gap-x-2 gap-y-1 px-2 py-1.5 sm:flex-nowrap sm:px-4">
        <Link
          href={paths.overview()}
          className="mr-2 font-semibold whitespace-nowrap"
        >
          <Wordmark />
        </Link>
        <nav className="scroll-thin order-last flex w-full min-w-0 gap-0.5 overflow-x-auto sm:order-none sm:w-auto sm:flex-1">
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
        <span className="flex-1 sm:hidden" />
        <button type="button" className={link} onClick={() => setAccount(true)}>
          Sign out…
        </button>
      </div>
      <SignOut open={account} onClose={() => setAccount(false)} />
    </header>
  );
}

function SignOut({ open, onClose }: { open: boolean; onClose: () => void }) {
  const confirm = useConfirm();
  const [error, setError] = useState("");
  const out = async (everywhere: boolean) => {
    if (
      everywhere &&
      !(await confirm({
        title: "Sign out everywhere",
        message:
          "Every browser signed in to f2b is signed out, this one too, and has to sign in again with the password.",
        confirm: "Sign out everywhere",
        danger: true,
      }))
    ) {
      return;
    }
    try {
      await (everywhere ? postAuthLogoutEverywhere() : postAuthLogout());
      leaveFor("/login");
    } catch (err) {
      setError(messageOf(err));
    }
  };
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Sign out"
      footer={
        <>
          <Button variant="danger" onClick={() => out(true)}>
            Everywhere…
          </Button>
          <Button variant="solid" onClick={() => out(false)}>
            Sign out
          </Button>
        </>
      }
    >
      <p className="text-sm text-muted">
        Sign this browser out, or every browser at once. Changing ADMIN_PASSWORD
        signs every browser out too.
      </p>
      {error ? <p className="text-sm text-accent">{error}</p> : null}
    </Dialog>
  );
}
