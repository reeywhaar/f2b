import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import { getFileReferences, postFileRename } from "@app/api/actions";
import { qk } from "@app/api/keys";
import { ApiError, messageOf } from "@app/api/transport";
import type { Kind } from "@app/api/types";
import { Button } from "@app/components/Button";
import { Dialog } from "@app/components/Dialog";
import { Field } from "@app/components/Field";
import { TextField } from "@app/components/TextField";
import { withExtension } from "@app/islands/app/NameDialog";

const bare = (n: string) => n.replace(/\.(local|conf)$/, "");

/**
 * A new name for a file. A jail names a filter or an action by its file's name, so the jails
 * that name this one can be changed with it, and the whole is tried on fail2ban as one change.
 */
export function RenameDialog({
  open,
  onClose,
  kind,
  name,
  version,
  onRenamed,
}: {
  open: boolean;
  onClose: () => void;
  kind: Kind;
  name: string;
  version: string;
  onRenamed: (to: string) => void;
}) {
  const [to, setTo] = useState(name);
  const [references, setReferences] = useState(true);

  const named = kind === "filters" || kind === "actions";
  const refs = useQuery({
    queryKey: qk.fileReferences(kind, name),
    queryFn: () => getFileReferences(kind, name),
    enabled: open && named,
  });
  const jails = refs.data?.files ?? [];
  const target = withExtension(to.trim());

  const rename = useMutation({
    mutationFn: () =>
      postFileRename(kind, name, {
        to: target,
        version,
        references: references && jails.length > 0,
      }),
    onSuccess: () => {
      onClose();
      onRenamed(target);
    },
  });

  // Each opening starts from the file's own name, with no word left from the last attempt.
  const { reset } = rename;
  useEffect(() => {
    if (open) {
      setTo(name);
      setReferences(true);
      reset();
    }
  }, [open, name, reset]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    rename.mutate();
  };

  const err = rename.error;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Rename ${name}`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="solid"
            type="submit"
            form="rename"
            disabled={rename.isPending || !to.trim() || target === name}
          >
            {rename.isPending ? "Renaming…" : "Rename"}
          </Button>
        </>
      }
    >
      <form id="rename" onSubmit={submit} className="flex flex-col gap-4">
        <Field
          label="New name"
          hint={
            named
              ? "A jail names this by the name without .local or .conf."
              : "The jails in it keep their names: those are the sections inside."
          }
        >
          <TextField
            data-autofocus
            className="w-full font-mono"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            autoComplete="off"
          />
        </Field>
        {named && jails.length > 0 ? (
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={references}
              onChange={(e) => setReferences(e.target.checked)}
            />
            <span>
              Change{" "}
              {jails.map((j, i) => (
                <span key={j.name}>
                  {i > 0 ? ", " : ""}
                  <code className="font-mono text-xs">
                    {j.kind === "jails" ? `jail.d/${j.name}` : j.name}
                  </code>
                </span>
              ))}{" "}
              to name <code className="font-mono text-xs">{bare(target)}</code>{" "}
              too. Without that, fail2ban refuses the rename: those jails would
              name a {kind === "filters" ? "filter" : "action"} that is gone.
            </span>
          </label>
        ) : null}
      </form>
      {err ? (
        <div className="flex flex-col gap-2">
          <p className="text-sm text-accent">{messageOf(err)}</p>
          {err instanceof ApiError && err.output ? (
            <pre className="scroll-thin max-h-60 overflow-auto rounded-md bg-(--color-code-bg) p-2 font-mono text-[11px] whitespace-pre-wrap">
              {err.output}
            </pre>
          ) : null}
        </div>
      ) : null}
    </Dialog>
  );
}
