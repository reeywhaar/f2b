import {
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import { getJails, getLogsByPath, postRegex } from "@app/api/actions";
import { qk } from "@app/api/keys";
import { messageOf } from "@app/api/transport";
import type { RegexLine, Verdict } from "@app/api/types";
import { Button } from "@app/components/Button";
import { Field } from "@app/components/Field";
import { Heading } from "@app/components/Heading";
import { PlusIcon } from "@app/components/icons/Icon";
import { SearchField } from "@app/components/SearchField";
import { Select } from "@app/components/Select";
import { TextField, fieldLook } from "@app/components/TextField";
import { count } from "@app/format";
import { draftFailregex } from "@app/islands/app/failregex";
import { LogPicker, PASTED } from "@app/islands/app/LogPicker";
import { NameDialog } from "@app/islands/app/NameDialog";
import { go, paths } from "@app/islands/app/route";
import { jailFor, seed } from "@app/islands/app/templates";

const lineCounts = [500, 2000, 10000];

/** How many lines are drawn at once: the last of those shown, which find narrows. */
const drawn = 2000;

/** How long the filter rests unchanged before it is tried again, once it has been tried. */
const settle = 800;

/**
 * fail2ban-regex over the filter as it is in the editor, saved or not, against the end of a log
 * a jail reads, any other among the logs the engine reads, or lines pasted here; and the lines
 * themselves, each marked with what the filter made of it, to find the one that should match
 * and start a failregex from it. Once it has run, a change to the filter runs it again.
 */
export function RegexTester({
  file,
  content,
  saved,
  dirty,
  onDraft,
}: {
  file: string;
  content: string;
  /** Whether the filter is on disk, where a jail can name it. */
  saved: boolean;
  /** Whether the editor has changes the disk has not. */
  dirty: boolean;
  /** Adds a failregex to the filter in the editor. */
  onDraft: (regex: string) => void;
}) {
  const jails = useQuery({ queryKey: qk.jails, queryFn: getJails });
  const bare = file.replace(/\.(local|conf)$/, "");
  const [filter, setFilter] = useState(bare);
  // A log's path, or PASTED for lines pasted.
  const [source, setSource] = useState("");
  const [text, setText] = useState("");
  const [lines, setLines] = useState(2000);
  const [live, setLive] = useState(false);
  const [note, setNote] = useState("");
  const [naming, setNaming] = useState(false);

  const all = jails.data?.jails ?? [];
  // The log of a jail that uses this filter, if one does.
  const picked =
    source ||
    (all.find((j) => j.filter === bare)?.logs[0] ??
      all.find((j) => j.logs.length)?.logs[0] ??
      PASTED);

  const tail = useQuery({
    queryKey: qk.logTail(picked, lines),
    queryFn: () => getLogsByPath(picked, lines),
    enabled: picked !== PASTED,
    refetchOnWindowFocus: false,
  });

  // What is tried: from where, how much, and what was pasted. A run's lines are shown while they
  // are still what would be tried.
  const from = JSON.stringify([picked, lines, picked === PASTED ? text : ""]);
  const run = useMutation({
    mutationFn: (_from: string) =>
      postRegex({
        filter,
        file,
        content,
        lines,
        ...(picked === PASTED ? { text } : { log: picked }),
      }),
  });
  const result = run.data && run.variables === from ? run.data : undefined;

  // What was last sent, so a change runs it again, and nothing else does.
  const sent = useRef("");
  const asked = JSON.stringify([from, filter, content]);
  const tryIt = () => {
    sent.current = asked;
    run.mutate(from);
  };
  useEffect(() => {
    if (!live || !filter || asked === sent.current) return;
    const timer = setTimeout(tryIt, settle);
    return () => clearTimeout(timer);
    // tryIt is this render's, and reads what asked says.
    // oxlint-disable-next-line react-hooks/exhaustive-deps
  }, [live, filter, asked]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    tryIt();
    setLive(true);
  };

  const draft = (line: string) => {
    const d = draftFailregex(line);
    onDraft(d.regex);
    setNote(
      d.address
        ? `Added to failregex in the editor: ${d.regex}`
        : `Added to failregex in the editor: ${d.regex}. No address was found in that line; a failregex needs <ADDR> where the address is.`,
    );
    setLive(true);
  };

  const rows: RegexLine[] = useMemo(
    () =>
      result
        ? result.lines
        : picked === PASTED
          ? []
          : (tail.data?.lines ?? []).map((t) => ({ text: t, verdict: "" })),
    [result, picked, tail.data],
  );
  const judged = !!result && result.lines.some((l) => l.verdict);
  const log = picked === PASTED ? undefined : picked;
  const s = result?.summary;

  return (
    <section>
      <Heading>Try it on a log</Heading>
      <form
        onSubmit={submit}
        className="flex flex-col gap-3 rounded-lg border border-line bg-bg px-(--h-padding) py-3"
      >
        <div className="grid gap-3 md:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)]">
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
        </div>
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
          <span className="flex-1" />
          {saved ? (
            <Button
              disabled={dirty}
              title={
                dirty
                  ? "Save the filter first: a jail names it as it is on disk"
                  : undefined
              }
              onClick={() => setNaming(true)}
            >
              New jail for this filter…
            </Button>
          ) : null}
        </div>
        {note ? <p className="text-xs break-all text-muted">{note}</p> : null}
        {run.isError ? (
          <p className="text-sm text-accent">{messageOf(run.error)}</p>
        ) : null}
        {picked !== PASTED || result ? (
          <TriedLines
            key={from}
            rows={rows}
            judged={judged}
            pending={picked !== PASTED && !result && tail.isPending}
            error={
              picked !== PASTED && !result && tail.isError
                ? messageOf(tail.error)
                : ""
            }
            onDraft={draft}
          />
        ) : null}
        {result ? (
          <details open={!result.ok} className="text-xs">
            <summary className="cursor-pointer text-muted select-none">
              What fail2ban-regex said
            </summary>
            <pre className="scroll-thin mt-1 max-h-80 overflow-auto rounded-md bg-(--color-code-bg) p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap">
              {result.output}
            </pre>
          </details>
        ) : null}
      </form>
      <NameDialog
        open={naming}
        onClose={() => setNaming(false)}
        title={`New jail for ${bare}`}
        suggest={bare}
        taken=""
        action="Open the jail"
        dir="jail.d"
        hint={`It reads ${log ?? "the log you name"} with ${filter.trim() || bare}, and is not saved until you save it.`}
        onName={(to) => {
          setNaming(false);
          seed("jails", to, jailFor(to, filter.trim() || bare, log));
          go(paths.file("jails", to, true));
        }}
      />
    </section>
  );
}

const verdicts: { value: Verdict | "all"; label: string }[] = [
  { value: "all", label: "All" },
  { value: "matched", label: "Matched" },
  { value: "missed", label: "Missed" },
  { value: "ignored", label: "Ignored" },
];

const dots: Record<Verdict | "all", string> = {
  all: "",
  matched: "bg-good",
  missed: "bg-faint",
  ignored: "bg-warn",
  "": "",
};

const looks: Record<Verdict, string> = {
  matched: "border-good bg-good/10 text-fg",
  ignored: "border-warn text-muted",
  missed: "border-transparent text-muted",
  "": "border-transparent text-fg",
};

/**
 * The lines tried, newest at the bottom as a log is, each marked with what the filter made of
 * it, to be narrowed to one kind or to those holding something. Each starts a failregex.
 */
function TriedLines({
  rows,
  judged,
  pending,
  error,
  onDraft,
}: {
  rows: RegexLine[];
  /** Whether the lines have verdicts yet. */
  judged: boolean;
  pending: boolean;
  error: string;
  onDraft: (line: string) => void;
}) {
  const [only, setOnly] = useState<Verdict | "all">("all");
  const [find, setFind] = useState("");
  const f = find.trim().toLowerCase();
  const counts = useMemo(() => {
    const c: Record<Verdict | "all", number> = {
      all: rows.length,
      matched: 0,
      missed: 0,
      ignored: 0,
      "": 0,
    };
    for (const r of rows) c[r.verdict]++;
    return c;
  }, [rows]);
  const shown = useMemo(
    () =>
      rows.filter(
        (r) =>
          (only === "all" || r.verdict === only) &&
          (!f || r.text.toLowerCase().includes(f)),
      ),
    [rows, only, f],
  );
  const start = Math.max(shown.length - drawn, 0);

  // The newest at the bottom, in view; a run again over the same lines stays where it is read.
  const box = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const el = box.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [rows.length, only, f]);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        {judged ? (
          <div role="group" aria-label="Show" className="flex flex-wrap gap-1">
            {verdicts.map((v) => (
              <button
                key={v.value}
                type="button"
                aria-pressed={only === v.value}
                onClick={() => setOnly(v.value)}
                className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs hover:bg-fill aria-pressed:bg-fill aria-pressed:font-medium"
              >
                {dots[v.value] ? (
                  <span
                    aria-hidden="true"
                    className={`size-2 rounded-full ${dots[v.value]}`}
                  />
                ) : null}
                {v.label}
                <span className="text-muted tabular-nums">
                  {count(counts[v.value])}
                </span>
              </button>
            ))}
          </div>
        ) : (
          <span className="text-xs text-muted">
            {pending
              ? "Reading…"
              : `${count(rows.length)} lines. Run fail2ban-regex to see which the filter matches.`}
          </span>
        )}
        <span className="flex-1" />
        <SearchField
          placeholder="Find in these lines"
          aria-label="Find in these lines"
          className="w-full sm:w-72"
          value={find}
          onChange={setFind}
        />
      </div>
      <div
        ref={box}
        className="scroll-thin max-h-[32rem] min-h-16 overflow-auto rounded-md border border-line bg-(--color-code-bg) py-1 font-mono text-[11px] leading-relaxed"
      >
        {error ? (
          <p className="px-3 py-1 text-accent">{error}</p>
        ) : pending ? null : shown.length ? (
          shown.slice(start).map((r, i) => (
            <div
              key={start + i}
              className={`group flex items-start gap-1 border-l-2 pr-1 pl-2 ${looks[r.verdict]}`}
            >
              <span className="min-w-0 flex-1 py-px whitespace-pre-wrap break-all">
                {marked(r.text, f)}
              </span>
              <button
                type="button"
                title="Start a failregex from this line"
                aria-label="Start a failregex from this line"
                onClick={() => onDraft(r.text)}
                className="shrink-0 rounded p-0.5 text-faint opacity-50 group-hover:opacity-100 hover:bg-control-hover hover:text-fg focus-visible:opacity-100"
              >
                <PlusIcon />
              </button>
            </div>
          ))
        ) : (
          <p className="px-3 py-1 text-muted">
            {rows.length ? "No line here has that." : "No lines."}
          </p>
        )}
      </div>
      {start > 0 ? (
        <p className="text-xs text-muted">
          These are the last {count(drawn)} of {count(shown.length)}; find
          narrows them.
        </p>
      ) : null}
    </div>
  );
}

/** A line with what was found in it marked. */
function marked(text: string, find: string): ReactNode {
  if (!find) return text;
  const parts: ReactNode[] = [];
  const lower = text.toLowerCase();
  let at = 0;
  for (let i = lower.indexOf(find); i >= 0; i = lower.indexOf(find, at)) {
    parts.push(text.slice(at, i));
    parts.push(
      <mark key={i} className="rounded-sm bg-warn/30 text-inherit">
        {text.slice(i, i + find.length)}
      </mark>,
    );
    at = i + find.length;
  }
  parts.push(text.slice(at));
  return parts;
}
