import { tokenizeText, type TokenStream } from "prism-code-editor/prism";

import "@app/editor/fail2ban";
import { languages } from "prism-code-editor/prism";

/** Every token as type:text, flattened. */
function flat(tokens: TokenStream): string[] {
  const out: string[] = [];
  for (const t of tokens) {
    if (typeof t === "string") continue;
    if (Array.isArray(t.content)) {
      out.push(...flat(t.content as TokenStream).map((s) => `${t.type}>${s}`));
    } else if (typeof t.content === "string") {
      out.push(`${t.type}:${t.content}`);
    } else {
      out.push(...flat([t.content]).map((s) => `${t.type}>${s}`));
    }
  }
  return out;
}

test("a filter reads as sections, keys, values, tags and interpolations", () => {
  const got = flat(
    tokenizeText(
      [
        "# Caddy's access log",
        "[Definition]",
        'failregex = ^{.*"remote_ip":"<HOST>".*%(dirs)s',
        '            ^{.*"uri":"<ADDR>"',
        "ignoreregex =",
      ].join("\n"),
      languages.fail2ban!,
    ),
  );
  expect(got).toContain("comment:# Caddy's access log");
  expect(got).toContain("section>section-name:Definition");
  expect(got).toContain("key:failregex");
  expect(got).toContain("value>tag:<HOST>");
  expect(got).toContain("value>interpolation:%(dirs)s");
  // Indented after a key, so the value carrying on rather than a key with a colon in it.
  expect(got).toContain("value>tag:<ADDR>");
  expect(got.filter((t) => t.startsWith("key:"))).toEqual([
    "key:failregex",
    "key:ignoreregex",
  ]);
});
