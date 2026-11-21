import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";

import { getLog } from "@app/api/actions";
import { messageOf } from "@app/api/transport";
import { Button } from "@app/components/Button";
import { DummyLines } from "@app/components/Dummy";
import { Frame } from "@app/components/Frame";
import { SearchField } from "@app/components/SearchField";

/** How many lines the page keeps, the engine's own window. */
const keep = 5000;

type Line = { seq: number; text: string };

/**
 * fail2ban's log as the engine captured it, following along: a line a few seconds after
 * fail2ban writes it. Paused, it stops asking.
 */
export function Log() {
  const [lines, setLines] = useState<Line[]>([]);
  const [error, setError] = useState("");
  // Whether the engine has answered at all: until it has, an empty log says nothing.
  const [read, setRead] = useState(false);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("");
  const cursor = useRef({ after: -1, epoch: "" });
  const box = useRef<HTMLDivElement>(null);
  const stuck = useRef(true);

  useEffect(() => {
    if (paused) return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const page = await getLog(cursor.current.after, cursor.current.epoch);
        if (stop) return;
        const restarted =
          cursor.current.epoch !== "" && page.epoch !== cursor.current.epoch;
        cursor.current = { after: page.last, epoch: page.epoch };
        setError("");
        setRead(true);
        if (page.lines.length > 0 || restarted) {
          setLines((old) => {
            const next = restarted
              ? [
                  ...old,
                  { seq: -1, text: "— the engine restarted —" },
                  ...page.lines,
                ]
              : [...old, ...page.lines];
            return next.length > keep ? next.slice(next.length - keep) : next;
          });
        }
      } catch (err) {
        if (!stop) setError(messageOf(err));
      }
      if (!stop) timer = setTimeout(tick, 2000);
    };
    tick();
    return () => {
      stop = true;
      clearTimeout(timer);
    };
  }, [paused]);

  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return f ? lines.filter((l) => l.text.toLowerCase().includes(f)) : lines;
  }, [lines, filter]);

  // Follows the end, unless somebody scrolled up to read.
  useLayoutEffect(() => {
    const el = box.current;
    if (el && stuck.current) el.scrollTop = el.scrollHeight;
  }, [shown]);

  return (
    <Frame fill>
      <div className="flex min-h-0 flex-1 flex-col gap-2">
        {/* Pause and the count, then the filter across from them; on a phone the filter wraps
            to a row of its own, the last, against the lines it narrows. */}
        <div className="flex flex-wrap items-center gap-2">
          <Button onClick={() => setPaused(!paused)} aria-pressed={paused}>
            {paused ? "Follow" : "Pause"}
          </Button>
          {read ? (
            <span className="text-xs text-muted tabular-nums">
              {filter
                ? `${shown.length} of ${lines.length} lines`
                : `${lines.length} lines`}
            </span>
          ) : null}
          <span className="flex-1" />
          <SearchField
            placeholder="Show only lines with…"
            aria-label="Show only lines with this"
            className="w-full sm:w-96 lg:w-xl"
            value={filter}
            onChange={setFilter}
          />
        </div>
        {error ? <p className="text-sm text-accent">{error}</p> : null}
        <div
          ref={box}
          onScroll={(e) => {
            const el = e.currentTarget;
            stuck.current =
              el.scrollHeight - el.scrollTop - el.clientHeight < 24;
          }}
          className="scroll-thin min-h-48 flex-1 overflow-auto rounded-lg border border-line bg-(--color-code-bg) px-(--h-padding) py-2 font-mono text-[11px] leading-relaxed"
        >
          {/* Not read yet and read empty are two things: the first is a shape where lines will
              be, or nothing at all beside the error that says why; only the second is told. */}
          {shown.length > 0 ? (
            shown.map((l, i) => (
              <div
                key={`${l.seq}-${i}`}
                className={`whitespace-pre-wrap break-all ${tone(l.text)}`}
              >
                {l.text}
              </div>
            ))
          ) : !read ? (
            error ? null : (
              <DummyLines count={6} />
            )
          ) : (
            <p className="text-muted">
              {lines.length > 0 ? "No line has that." : "Nothing logged yet."}
            </p>
          )}
        </div>
      </div>
    </Frame>
  );
}

/** A line's look from its level, and bans and unbans picked out. */
function tone(text: string): string {
  if (/\b(ERROR|CRITICAL)\b/.test(text)) return "text-accent";
  if (/\bWARNING\b/.test(text)) return "text-warn";
  if (/\] Ban /.test(text)) return "font-semibold text-fg";
  if (/\] Unban /.test(text)) return "text-good";
  if (text.startsWith("— ")) return "text-faint italic";
  return "text-muted";
}
