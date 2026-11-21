import { useEffect, useState, type FormEvent } from "react";

import { Button } from "@app/components/Button";
import { Dialog } from "@app/components/Dialog";
import { Field } from "@app/components/Field";
import { TextField } from "@app/components/TextField";

const fileName = /^[A-Za-z0-9][A-Za-z0-9_.@-]{0,95}$/;

/** A name as fail2ban reads it: .local unless it says .conf. */
export const withExtension = (n: string) =>
  n.endsWith(".local") || n.endsWith(".conf") ? n : `${n}.local`;

/** A file name, asked for, and handed on once it is one fail2ban would read. */
export function NameDialog({
  open,
  onClose,
  title,
  suggest,
  taken,
  action,
  hint,
  placeholder,
  dir,
  onName,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  suggest: string;
  /** A name the answer may not be: the file's own. */
  taken: string;
  action: string;
  hint: string;
  placeholder?: string;
  /** Where the file goes, jail.d and the like, said under the field when given. */
  dir?: string;
  onName: (name: string) => void;
}) {
  const [name, setName] = useState(suggest);
  const [error, setError] = useState("");
  useEffect(() => {
    if (open) {
      setName(suggest);
      setError("");
    }
  }, [open, suggest]);

  const target = withExtension(name.trim());
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!fileName.test(target)) {
      setError(
        "Letters, digits, dots, dashes and underscores, starting with a letter or a digit.",
      );
      return;
    }
    onName(target);
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="solid"
            type="submit"
            form="name-dialog"
            disabled={!name.trim() || target === taken}
          >
            {action}
          </Button>
        </>
      }
    >
      <form id="name-dialog" onSubmit={submit}>
        <Field label="Name" hint={hint}>
          <TextField
            data-autofocus
            className="w-full font-mono"
            placeholder={placeholder}
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoComplete="off"
          />
        </Field>
      </form>
      {dir ? (
        <p className="text-sm text-muted">
          It is saved as{" "}
          <code className="font-mono text-xs">
            {dir}/{withExtension(name.trim() || "…")}
          </code>{" "}
          once fail2ban accepts it.
        </p>
      ) : null}
      {error ? <p className="text-sm text-accent">{error}</p> : null}
    </Dialog>
  );
}
