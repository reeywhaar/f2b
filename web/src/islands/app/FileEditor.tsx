import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  deleteFile,
  getFile,
  getStock,
  postCheck,
  putFile,
} from "@app/api/actions";
import { qk } from "@app/api/keys";
import { ApiError, messageOf } from "@app/api/transport";
import type { Kind } from "@app/api/types";
import { Button } from "@app/components/Button";
import { useConfirm } from "@app/components/Confirm";
import { DummyRows } from "@app/components/Dummy";
import { Frame } from "@app/components/Frame";
import { Menu } from "@app/components/Menu";
import { CodeEditor } from "@app/editor/CodeEditor";
import { ago } from "@app/format";
import { addFailregex } from "@app/islands/app/failregex";
import { RegexTester } from "@app/islands/app/RegexTester";
import { NameDialog } from "@app/islands/app/NameDialog";
import { Crumbs } from "@app/islands/app/Crumbs";
import { RenameDialog } from "@app/islands/app/RenameDialog";
import { go, hold, paths } from "@app/islands/app/route";
import { seed, seeded, templateFor, unseed } from "@app/islands/app/templates";

/** The headings on the Config page each kind is listed under. */
const sections: Record<Kind, string> = {
  jails: "Jails",
  filters: "Filters",
  actions: "Actions",
  settings: "Settings",
};

const dirs: Record<Kind, string> = {
  jails: "jail.d/",
  filters: "filter.d/",
  actions: "action.d/",
  settings: "",
};

/** What the last thing done said, kept on screen until the next. */
type Outcome = {
  tone: "good" | "warn" | "bad";
  message: string;
  output?: string;
  reopen?: boolean;
} | null;

/**
 * One file, in the editor, until Save. Save is tried on fail2ban first, against everything else
 * that is edited, and only written if fail2ban would start with it; then fail2ban reloads.
 */
export function FileEditor({
  kind,
  name,
  fresh,
}: {
  kind: Kind;
  name: string;
  fresh: boolean;
}) {
  const client = useQueryClient();
  const confirm = useConfirm();
  const file = useQuery({
    queryKey: qk.file(kind, name),
    queryFn: () => getFile(kind, name),
    enabled: !fresh,
    // What is in the editor is the user's until they ask for the file again.
    refetchOnWindowFocus: false,
    staleTime: Infinity,
  });
  const stock = useQuery({
    queryKey: qk.stock,
    queryFn: getStock,
    enabled: fresh && (kind === "filters" || kind === "actions"),
  });

  // What was opened, the version it was, and what is in the editor now.
  const [base, setBase] = useState<{ content: string; version: string } | null>(
    null,
  );
  const [draft, setDraft] = useState("");
  const [outcome, setOutcome] = useState<Outcome>(null);
  const [renaming, setRenaming] = useState(false);
  const [duplicating, setDuplicating] = useState(false);

  useEffect(() => {
    if (base) return;
    if (fresh) {
      if (stock.isPending && (kind === "filters" || kind === "actions")) return;
      const content = seeded(kind, name) ?? templateFor(kind, name, stock.data);
      setBase({ content: "", version: "" });
      setDraft(content);
    } else if (file.data) {
      setBase({ content: file.data.content, version: file.data.file.version });
      setDraft(file.data.content);
    }
  }, [base, fresh, file.data, stock.isPending, stock.data, kind, name]);

  const dirty = base !== null && (fresh || draft !== base.content);
  const dirtyRef = useRef(dirty);
  dirtyRef.current = dirty;

  // Leaving with changes asks first: within the island in the app's own dialog, and out of the
  // document in the browser's.
  useEffect(() => {
    hold(
      async () =>
        !dirtyRef.current ||
        confirm({
          title: "Leave without saving",
          message: `The changes to ${name} are not saved, and are lost.`,
          confirm: "Leave",
          danger: true,
        }),
    );
    const unload = (e: BeforeUnloadEvent) => {
      if (dirtyRef.current) e.preventDefault();
    };
    window.addEventListener("beforeunload", unload);
    return () => {
      hold(null);
      window.removeEventListener("beforeunload", unload);
    };
  }, [confirm, name]);

  const refresh = () => {
    client.invalidateQueries({ queryKey: qk.files });
    client.invalidateQueries({ queryKey: qk.jails });
    client.invalidateQueries({ queryKey: qk.engine });
  };

  const save = useMutation({
    mutationFn: () =>
      putFile(kind, name, { content: draft, version: base?.version ?? "" }),
    onMutate: () => setOutcome(null),
    onSuccess: (applied) => {
      unseed(kind, name);
      const saved = applied.file!;
      setBase({ content: draft, version: saved.version });
      client.setQueryData(qk.file(kind, name), { file: saved, content: draft });
      refresh();
      setOutcome(
        applied.reload.ok
          ? {
              tone: "good",
              message: "Saved, and fail2ban reloaded with it.",
              output: applied.reload.output,
            }
          : {
              tone: "warn",
              message:
                "Saved, but fail2ban's reload failed. The file is on disk; fail2ban runs as it was until the reload succeeds.",
              output: applied.reload.output,
            },
      );
      // Saved, so leaving the address that said "new" is not leaving changes behind.
      dirtyRef.current = false;
      if (fresh) go(paths.file(kind, name), true);
    },
    onError: (err) => setOutcome(refusal(err)),
  });

  const check = useMutation({
    mutationFn: () => postCheck({ kind, name, content: draft }),
    onMutate: () => setOutcome(null),
    onSuccess: (r) =>
      setOutcome(
        r.ok
          ? {
              tone: "good",
              message: "fail2ban would start with this.",
              output: r.output,
            }
          : {
              tone: "bad",
              message: "fail2ban would refuse this.",
              output: r.output,
            },
      ),
    onError: (err) => setOutcome(refusal(err)),
  });

  const remove = useMutation({
    mutationFn: () => deleteFile(kind, name, base?.version ?? ""),
    onSuccess: () => {
      dirtyRef.current = false;
      client.removeQueries({ queryKey: qk.file(kind, name) });
      refresh();
      go(paths.config);
    },
    onError: (err) => setOutcome(refusal(err)),
  });

  const reopen = async () => {
    if (
      dirty &&
      !(await confirm({
        title: "Open it again",
        message: `What is on disk now replaces what is in the editor, and the changes made here are lost.`,
        confirm: "Open it again",
        danger: true,
      }))
    ) {
      return;
    }
    const again = await file.refetch();
    if (again.data) {
      setBase({
        content: again.data.content,
        version: again.data.file.version,
      });
      setDraft(again.data.content);
      setOutcome(null);
    }
  };

  const busy = save.isPending || check.isPending || remove.isPending;
  const loading = !fresh && file.isPending;

  const renamed = (to: string) => {
    // What was on disk under the old name is the new name's now.
    dirtyRef.current = false;
    client.removeQueries({ queryKey: qk.file(kind, name) });
    refresh();
    go(paths.file(kind, to), true);
  };

  return (
    <Frame>
      {/* The title row belongs to the editor under it, not a section of its own. */}
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <Crumbs section={sections[kind]} name={name} />
          {fresh ? (
            <span className="rounded bg-fill px-1.5 py-0.5 text-xs text-muted">
              new
            </span>
          ) : file.data ? (
            <span className="text-xs text-faint">
              changed {ago(file.data.file.modified)}
            </span>
          ) : null}
          <span className="flex-1" />
          {/* What is done with the change has the row; what is done to the file, now and then,
              is behind the menu beside it. One row at any width. */}
          <div className="ml-auto flex items-center gap-2">
            {!fresh && file.data ? (
              <Menu
                label="More for this file"
                items={[
                  ...(kind !== "settings"
                    ? [
                        {
                          label: "Rename…",
                          disabled: busy || dirty,
                          title: dirty
                            ? "Save or discard the changes first"
                            : undefined,
                          onSelect: () => setRenaming(true),
                        },
                        {
                          label: "Duplicate…",
                          disabled: busy,
                          onSelect: () => setDuplicating(true),
                        },
                      ]
                    : []),
                  {
                    label: "Delete…",
                    danger: true,
                    disabled: busy,
                    onSelect: async () => {
                      if (
                        await confirm({
                          title: `Delete ${name}`,
                          message:
                            kind === "jails"
                              ? "The file goes, and fail2ban reloads without it: its jails stop, and their bans are lifted. fail2ban's database keeps their history."
                              : "The file goes, if fail2ban would still start without it, and fail2ban reloads.",
                          confirm: "Delete",
                          danger: true,
                        })
                      ) {
                        remove.mutate();
                      }
                    },
                  },
                ]}
              />
            ) : null}
            {dirty && !fresh ? (
              <Button
                disabled={busy}
                onClick={() => base && setDraft(base.content)}
              >
                Discard
              </Button>
            ) : null}
            <Button disabled={busy || loading} onClick={() => check.mutate()}>
              {check.isPending ? "Checking…" : "Check"}
            </Button>
            <Button
              variant="solid"
              disabled={busy || loading || !dirty}
              onClick={() => save.mutate()}
            >
              {save.isPending ? "Saving…" : "Save"}
            </Button>
          </div>
        </div>
        {file.isError ? (
          <p className="text-sm text-accent">{messageOf(file.error)}</p>
        ) : base === null ? (
          <DummyRows count={8} />
        ) : (
          <div className="flex flex-col gap-3">
            <CodeEditor
              label={`${name}, editable`}
              value={draft}
              onChange={setDraft}
              onSave={() => {
                if (dirty && !busy) save.mutate();
              }}
            />
            <p className="text-xs text-faint">
              Cmd-S or Ctrl-S saves; Cmd-F or Ctrl-F finds. Tab indents, which
              carries a value on to the next line. Escape, then Tab, leaves the
              editor.
            </p>
            <OutcomeView outcome={outcome} onReopen={reopen} />
          </div>
        )}
      </div>

      {kind === "filters" && base !== null ? (
        <RegexTester
          file={name}
          content={draft}
          saved={!fresh}
          dirty={dirty}
          onDraft={(regex) => setDraft((d) => addFailregex(d, regex))}
        />
      ) : null}
      <NameDialog
        open={duplicating}
        onClose={() => setDuplicating(false)}
        title={`Duplicate ${name}`}
        suggest={`${name.replace(/\.(local|conf)$/, "")}-copy`}
        taken={name}
        action="Open the copy"
        dir={dirs[kind].replace(/\/$/, "")}
        hint="A new file with what is in the editor now, as it is, not saved until you save it."
        onName={(to) => {
          setDuplicating(false);
          seed(kind, to, draft);
          go(paths.file(kind, to, true));
        }}
      />
      <RenameDialog
        open={renaming}
        onClose={() => setRenaming(false)}
        kind={kind}
        name={name}
        version={base?.version ?? ""}
        onRenamed={renamed}
      />
    </Frame>
  );
}

function refusal(err: unknown): Outcome {
  if (err instanceof ApiError && err.code === "config_rejected") {
    return { tone: "bad", message: err.message, output: err.output };
  }
  if (err instanceof ApiError && err.code === "conflict") {
    return { tone: "bad", message: err.message, reopen: true };
  }
  return { tone: "bad", message: messageOf(err) };
}

const tones = {
  good: "border-good/40 text-good",
  warn: "border-warn/50 text-warn",
  bad: "border-accent/50 text-accent",
};

function OutcomeView({
  outcome,
  onReopen,
}: {
  outcome: Outcome;
  onReopen: () => void;
}) {
  if (!outcome) return null;
  const long = (outcome.output ?? "").includes("\n");
  return (
    <div
      role="status"
      className={`flex flex-col gap-2 rounded-lg border bg-bg px-(--h-padding) py-3 ${tones[outcome.tone]}`}
    >
      <div className="flex flex-wrap items-center gap-3">
        <p className="flex-1 text-sm font-medium">{outcome.message}</p>
        {outcome.reopen ? (
          <Button onClick={onReopen}>Open it again…</Button>
        ) : null}
      </div>
      {outcome.output && outcome.output !== "OK" ? (
        // A refusal's words are the point, and are shown; a success's are there if wanted.
        <details open={outcome.tone !== "good" || !long}>
          <summary className="cursor-pointer text-xs text-muted select-none">
            What fail2ban said
          </summary>
          <pre className="scroll-thin mt-1 max-h-80 overflow-auto rounded-md bg-(--color-code-bg) p-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap text-fg">
            {outcome.output}
          </pre>
        </details>
      ) : null}
    </div>
  );
}
