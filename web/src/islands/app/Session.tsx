import { useState } from "react";

import { postAuthLogout, postAuthLogoutEverywhere } from "@app/api/actions";
import { messageOf } from "@app/api/transport";
import { Button } from "@app/components/Button";
import { useConfirm } from "@app/components/Confirm";
import { Heading } from "@app/components/Heading";
import { leaveFor } from "@app/leave";

/**
 * Signing out, at the end of Config: something done rarely and on purpose, kept out of the way
 * of everything done often.
 */
export function Session() {
  const confirm = useConfirm();
  const [error, setError] = useState("");
  const out = async (everywhere: boolean) => {
    setError("");
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
    <section>
      <Heading>Signing in</Heading>
      <div className="flex flex-col gap-3">
        <p className="max-w-3xl text-sm text-muted">
          There is one password, ADMIN_PASSWORD in the web&rsquo;s environment.
          A browser stays signed in for thirty days from its last visit;
          changing the password signs every browser out.
        </p>
        <div className="flex flex-wrap gap-2">
          <Button size="bar" onClick={() => out(false)}>
            Sign out
          </Button>
          <Button variant="danger" size="bar" onClick={() => out(true)}>
            Sign out everywhere…
          </Button>
        </div>
        {error ? <p className="text-sm text-accent">{error}</p> : null}
      </div>
    </section>
  );
}
