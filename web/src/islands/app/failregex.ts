/**
 * Where a date is in a line, the ways logs write one: ISO 8601 and its kin, an access log's,
 * syslog's and ctime's, and seconds since 1970.
 */
const dates = [
  /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?/,
  /\d{4}\/\d{2}\/\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?/,
  /\d{1,2}\/[A-Z][a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?/,
  /(?:[A-Z][a-z]{2} )?[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}(?: \d{4})?/,
  /\b1\d{9}(?:\.\d+)?\b/,
];

type Span = { start: number; end: number };

/** The first date in a line, the longest of those that start there. */
function dateIn(line: string): Span | null {
  let found: Span | null = null;
  for (const form of dates) {
    const m = form.exec(line);
    if (!m) continue;
    const span = { start: m.index, end: m.index + m[0].length };
    if (
      !found ||
      span.start < found.start ||
      (span.start === found.start && span.end > found.end)
    ) {
      found = span;
    }
  }
  return found;
}

const ipv4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const ipv6 = /(?<![\w:.])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])/g;

/**
 * The first address in a line outside its date: IPv4, else IPv6. A time is digits and colons
 * too, so an IPv6 address is taken only with a "::" in it, or as eight groups of one.
 */
function addressIn(line: string, date: Span | null): Span | null {
  const outside = (s: Span) =>
    !date || s.end <= date.start || s.start >= date.end;
  for (const m of line.matchAll(ipv4)) {
    const s = { start: m.index, end: m.index + m[0].length };
    if (outside(s) && m[0].split(".").every((o) => Number(o) <= 255)) return s;
  }
  for (const m of line.matchAll(ipv6)) {
    const s = { start: m.index, end: m.index + m[0].length };
    if (outside(s) && (m[0].includes("::") || m[0].split(":").length === 8)) {
      return s;
    }
  }
  return null;
}

/**
 * Text as itself in a failregex: escaped for Python's re, a number on its own as any number, as
 * a pid or a port is another in the next line, and % doubled, as fail2ban's configuration reads
 * %(…)s as a value of its own. # and ; are escaped too: a line of a value that starts with one
 * is a comment.
 */
function literal(text: string): string {
  return text
    .split(/(\b\d+\b)/)
    .map((part, i) =>
      i % 2 === 1 ? "\\d+" : part.replace(/[.*+?^${}()|[\]\\#;]/g, "\\$&"),
    )
    .join("")
    .replace(/%/g, "%%");
}

/**
 * A failregex to start from, made of one line of a log.
 *
 * fail2ban takes the date out of a line before it tries a failregex on what is left, and keeps
 * what was around it: the space before the rest of a syslog line, an access log's "[]". It also
 * does not know every date for one. So a date at the start goes, with the space after it, and
 * one further in becomes .*, which matches where it was either way; and the failregex is not
 * anchored, as what is left before the rest of the line is fail2ban's to say. The address
 * becomes <ADDR>, and the rest is the line itself.
 */
export function draftFailregex(line: string): {
  regex: string;
  /** Whether an address was found: a failregex needs one, and without one it is the user's to place. */
  address: boolean;
} {
  const date = dateIn(line);
  const address = addressIn(line, date);
  const marks = [
    ...(date ? [{ ...date, kind: "date" as const }] : []),
    ...(address ? [{ ...address, kind: "address" as const }] : []),
  ].toSorted((a, b) => a.start - b.start);

  let out = "";
  let at = 0;
  for (const m of marks) {
    out += literal(line.slice(at, m.start));
    if (m.kind === "address") out += "<ADDR>";
    else if (line.slice(0, m.start).trim() !== "") out += ".*";
    at = m.end;
    // The date led the line: what follows starts the failregex.
    if (m.kind === "date" && out.trim() === "") {
      while (at < line.length && /\s/.test(line[at]!)) at++;
    }
  }
  out += literal(line.slice(at));
  return { regex: out.trim(), address: address !== null };
}

const definition = /^\s*\[Definition\]\s*$/;
const failregexKey = /^failregex\s*[=:]\s*/;

/**
 * A filter's text with one more failregex: on the failregex line when it says nothing yet, else
 * on a line of its own under the ones it has, indented as they are. A filter without one gets
 * one, under [Definition], which it gets too when it has none.
 */
export function addFailregex(content: string, regex: string): string {
  const lines = content.split("\n");
  const head = lines.findIndex((l) => definition.test(l));
  if (head < 0) {
    const gap =
      content === "" || content.endsWith("\n\n")
        ? ""
        : content.endsWith("\n")
          ? "\n"
          : "\n\n";
    return `${content}${gap}[Definition]\nfailregex = ${regex}\n`;
  }
  let end = lines.findIndex((l, i) => i > head && /^\s*\[/.test(l));
  if (end < 0) end = lines.length;
  const key = lines.findIndex(
    (l, i) => i > head && i < end && failregexKey.test(l),
  );
  if (key < 0) {
    lines.splice(head + 1, 0, `failregex = ${regex}`);
    return lines.join("\n");
  }
  const keyLine = lines[key]!;
  const lead = failregexKey.exec(keyLine)![0];
  let last = key;
  while (last + 1 < end && /^[ \t]+\S/.test(lines[last + 1]!)) last++;
  if (keyLine.slice(lead.length).trim() === "" && last === key) {
    lines[key] = `${lead.trimEnd()} ${regex}`;
    return lines.join("\n");
  }
  const indent =
    last > key ? /^[ \t]+/.exec(lines[last]!)![0] : " ".repeat(lead.length);
  lines.splice(last + 1, 0, `${indent}${regex}`);
  return lines.join("\n");
}
