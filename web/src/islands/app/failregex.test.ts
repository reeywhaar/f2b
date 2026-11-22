import { describe, expect, it } from "vitest";

import { addFailregex, draftFailregex } from "@app/islands/app/failregex";
import { jailFor } from "@app/islands/app/templates";

describe("a failregex drafted from a line", () => {
  it.each([
    [
      "syslog, its date leading the line and gone with the space after it",
      "Nov 22 10:05:01 host sshd[2]: Failed password for root from 198.51.100.4 port 22 ssh2",
      "host sshd\\[\\d+\\]: Failed password for root from <ADDR> port \\d+ ssh2",
    ],
    [
      "JSON, its date inside it as .*",
      '{"time":"2026-11-22T18:09:59.595146084Z","level":"WARN","msg":"password refused","ip":"192.0.2.216"}',
      '\\{"time":".*","level":"WARN","msg":"password refused","ip":"<ADDR>"\\}',
    ],
    [
      "an access log, the address before the date, and a % doubled",
      '192.0.2.7 - - [22/Nov/2026:10:00:00 +0000] "GET /wp-login.php?q=%41 HTTP/1.1" 404 12',
      '<ADDR> - - \\[.*\\] "GET /wp-login\\.php\\?q=%%\\d+ HTTP/\\d+\\.\\d+" \\d+ \\d+',
    ],
    [
      "seconds since 1970",
      '{"ts":1795369769.123,"request":{"remote_ip":"192.0.2.9"},"status":404}',
      '\\{"ts":.*,"request":\\{"remote_ip":"<ADDR>"\\},"status":\\d+\\}',
    ],
    [
      "an IPv6 address, beside a time it is not",
      "2026-11-22 10:05:01 Failed password for root from 2001:db8::1 port 22",
      "Failed password for root from <ADDR> port \\d+",
    ],
  ])("%s", (_, line, regex) => {
    expect(draftFailregex(line)).toEqual({ regex, address: true });
  });

  it("says when there was no address to put <ADDR> for", () => {
    expect(draftFailregex("kernel: #1 something; happened")).toEqual({
      regex: "kernel: \\#\\d+ something\\; happened",
      address: false,
    });
  });
});

describe("a failregex added to a filter", () => {
  it("fills a failregex that says nothing yet", () => {
    expect(
      addFailregex("[Definition]\nfailregex = \nignoreregex =\n", "^x <ADDR>"),
    ).toBe("[Definition]\nfailregex = ^x <ADDR>\nignoreregex =\n");
  });

  it("goes under the ones there are, indented as they are", () => {
    expect(addFailregex("[Definition]\nfailregex = ^a\n", "^b")).toBe(
      "[Definition]\nfailregex = ^a\n            ^b\n",
    );
    expect(
      addFailregex(
        "[Definition]\nfailregex = ^a\n    ^b\n\nignoreregex =\n",
        "^c",
      ),
    ).toBe("[Definition]\nfailregex = ^a\n    ^b\n    ^c\n\nignoreregex =\n");
  });

  it("makes a failregex, and a [Definition] for it, where there are none", () => {
    expect(addFailregex("[Definition]\nignoreregex =\n", "^a")).toBe(
      "[Definition]\nfailregex = ^a\nignoreregex =\n",
    );
    expect(addFailregex("[Init]\nmaxlines = 1\n", "^a")).toBe(
      "[Init]\nmaxlines = 1\n\n[Definition]\nfailregex = ^a\n",
    );
  });

  it("leaves a failregex in another section alone", () => {
    expect(addFailregex("[Init]\nfailregex = no\n\n[Definition]\n", "^a")).toBe(
      "[Init]\nfailregex = no\n\n[Definition]\nfailregex = ^a\n",
    );
  });
});

describe("a jail for a filter", () => {
  it("reads the log tried with the filter tried", () => {
    const jail = jailFor("web.local", "web[mode=x]", "/srv/logs/$1.log");
    expect(jail).toMatch(/^\[web\]$/m);
    expect(jail).toMatch(/^filter {4}= web\[mode=x\]$/m);
    expect(jail).toMatch(/^logpath {3}= \/srv\/logs\/\$1\.log$/m);
  });
});
