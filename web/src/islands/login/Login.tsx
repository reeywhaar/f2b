import { useState, type FormEvent } from "react";

import { postAuthLogin } from "@app/api/actions";
import { messageOf } from "@app/api/transport";
import { Button } from "@app/components/Button";
import { TextField } from "@app/components/TextField";
import { Wordmark } from "@app/components/Wordmark";
import { leaveFor } from "@app/leave";

/**
 * The only document a signed-out visitor loads: a few kilobytes instead of the whole
 * application. The password is the one the web's environment names, ADMIN_PASSWORD.
 */
export function Login() {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await postAuthLogin({ password });
      leaveFor("/");
    } catch (err) {
      setError(messageOf(err));
      setBusy(false);
    }
  };

  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-sm flex-col justify-center gap-6 px-(--h-padding)">
      <h1 className="text-2xl font-semibold">
        <Wordmark />
      </h1>
      <form className="flex flex-col gap-3" onSubmit={submit}>
        {/* A username nobody types, so a password manager files this under something. */}
        <input
          type="text"
          name="username"
          autoComplete="username"
          value="admin"
          readOnly
          hidden
        />
        <TextField
          name="password"
          type="password"
          autoComplete="current-password"
          placeholder="Password"
          aria-label="Password"
          className="w-full"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoFocus
        />
        {error ? <p className="text-sm text-accent">{error}</p> : null}
        <Button
          type="submit"
          variant="solid"
          className="justify-center"
          disabled={busy || password === ""}
        >
          Sign in
        </Button>
      </form>
    </main>
  );
}
