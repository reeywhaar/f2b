import { useState, type FormEvent } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import { getJails, postRegex } from "@app/api/actions";
import { qk } from "@app/api/keys";
import { messageOf } from "@app/api/transport";
import { Button } from "@app/components/Button";
import { Field, Fields } from "@app/components/Field";
import { Heading } from "@app/components/Heading";
import { Select } from "@app/components/Select";
import { TextField, fieldLook } from "@app/components/TextField";
import { count } from "@app/format";

const lineCounts = [500, 2000, 10000];

/**
 * fail2ban-regex over the filter as it is in the editor, saved or not: against the end of a log
 * a jail reads, any other file the engine can read, or lines pasted here.
 */
export function RegexTester({
  file,
  content,
}: {
  file: string;
  content: string;
}) {
  const jails = useQuery({ queryKey: qk.jails, queryFn: getJails });
  const bare = file.replace(/\.(local|conf)$/, "");
  const [filter, setFilter] = useState(bare);
  // A log's path, "other" for one typed, or "text" for lines pasted.
  const [source, setSource] = useState("");
  const [path, setPath] = useState("");
  const [text, setText] = useState("");
  const [lines, setLines] = useState(2000);

  const logs = [
    ...new Set(
      (jails.data?.jails ?? []).flatMap((j) => j.logs.map((l) => `${l}`)),
    ),
  ];
  const usedBy = (log: string) =>
    (jails.data?.jails ?? [])
      .filter((j) => j.logs.includes(log))
      .map((j) => j.name);
  // The log of a jail that uses this filter, if one does.
  const picked =
    source ||
    (jails.data?.jails.find((j) => j.filter === bare)?.logs[0] ??
      logs[0] ??
      "text");

  const run = useMutation({
    mutationFn: () =>
      postRegex({
        filter,
        file,
        content,
        lines,
        ...(picked === "text"
          ? { text }
          : { log: picked === "other" ? path.trim() : picked }),
      }),
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    run.mutate();
  };

  const s = run.data?.summary;
  return (
    <section>
      <Heading>Try it on a log</Heading>
      <form
        onSubmit={submit}
        className="flex flex-col gap-3 rounded-lg border border-line bg-bg px-(--h-padding) py-3"
      >
        <Fields>
          <Field
            label="Lines from"
            hint="The end of a log a running jail reads, another file the engine can read, or lines pasted here. The filter is what is in the editor, saved or not."
          >
            <Select
              className="w-full"
              value={picked}
              onChange={(e) => setSource(e.target.value)}
            >
              {logs.map((l) => (
                <option key={l} value={l}>
                  {l} ({usedBy(l).join(", ")})
                </option>
              ))}
              <option value="other">Another file…</option>
              <option value="text">Lines pasted here</option>
            </Select>
          </Field>
          <Field
            label="Filter"
            hint="As a jail names it: this file's name, with options in brackets if it takes any, as sshd[mode=aggressive]."
          >
            <TextField
              className="w-full font-mono"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          </Field>
          {picked === "other" ? (
            <Field
              label="File"
              hint="A path inside the engine's container, such as /remotelogs/docker/caddy.log."
            >
              <TextField
                className="w-full font-mono"
                placeholder="/var/log/auth.log"
                value={path}
                onChange={(e) => setPath(e.target.value)}
              />
            </Field>
          ) : null}
          {picked !== "text" ? (
            <Field label="How many" hint="From the end of the log.">
              <Select
                className="w-full"
                value={lines}
                onChange={(e) => setLines(Number(e.target.value))}
              >
                {lineCounts.map((n) => (
                  <option key={n} value={n}>
                    The last {count(n)} lines
                  </option>
                ))}
              </Select>
            </Field>
          ) : null}
        </Fields>
        {picked === "text" ? (
          <textarea
            aria-label="Lines to try"
            className={`${fieldLook} min-h-32 w-full py-2 font-mono text-xs`}
            spellCheck={false}
            placeholder="Paste log lines here"
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
        ) : null}
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={run.isPending || !filter}>
            {run.isPending ? "Running…" : "Run fail2ban-regex"}
          </Button>
          {s ? (
            <p className="text-sm tabular-nums" role="status">
              <span
                className={
                  s.matched > 0 ? "font-semibold text-good" : "font-semibold"
                }
              >
                {count(s.matched)} matched
              </span>
              <span className="text-muted">
                {" "}
                of {count(s.lines)} lines; {count(s.missed)} missed,{" "}
                {count(s.ignored)} ignored
              </span>
            </p>
          ) : null}
        </div>
        {run.isError ? (
          <p className="text-sm text-accent">{messageOf(run.error)}</p>
        ) : null}
        {run.data ? (
          <pre className="scroll-thin max-h-[32rem] overflow-auto rounded-md bg-(--color-code-bg) p-3 font-mono text-[11px] leading-relaxed">
            {run.data.output}
          </pre>
        ) : null}
      </form>
    </section>
  );
}
