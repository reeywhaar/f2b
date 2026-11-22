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
import { LogPicker, PASTED } from "@app/islands/app/LogPicker";

const lineCounts = [500, 2000, 10000];

/**
 * fail2ban-regex over the filter as it is in the editor, saved or not: against the end of a log
 * a jail reads, any other among the logs the engine reads, or lines pasted here.
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
  // A log's path, or PASTED for lines pasted.
  const [source, setSource] = useState("");
  const [text, setText] = useState("");
  const [lines, setLines] = useState(2000);

  const all = jails.data?.jails ?? [];
  // The log of a jail that uses this filter, if one does.
  const picked =
    source ||
    (all.find((j) => j.filter === bare)?.logs[0] ??
      all.find((j) => j.logs.length)?.logs[0] ??
      PASTED);

  const run = useMutation({
    mutationFn: () =>
      postRegex({
        filter,
        file,
        content,
        lines,
        ...(picked === PASTED ? { text } : { log: picked }),
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
            hint="The end of a log a running jail reads, any other in the directories the engine reads logs from, or lines pasted here. The filter is what is in the editor, saved or not."
          >
            <LogPicker
              className="w-full"
              value={picked}
              onChange={setSource}
              jails={all}
            />
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
          {picked !== PASTED ? (
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
        {picked === PASTED ? (
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
