import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { RegexTester } from "@app/islands/app/RegexTester";
import { seeded } from "@app/islands/app/templates";
import { mount } from "@app/test/harness";

const getJails = vi.fn();
const getLogsByPath = vi.fn();
const postRegex = vi.fn();

vi.mock("@app/api/actions", () => ({
  getJails: () => getJails(),
  getLogsByPath: (p: string, n?: number) => getLogsByPath(p, n),
  postRegex: (b: unknown) => postRegex(b),
  getLogs: () => Promise.resolve({ roots: [] }),
}));

afterEach(() => vi.clearAllMocks());

const failed = "Nov 22 10:05:01 host app[7]: login failed for 192.0.2.1";
const fine = "Nov 22 10:05:02 host app[7]: login ok";

function tester(dirty = false) {
  getJails.mockResolvedValue({
    jails: [{ name: "app", filter: "app", logs: ["/var/log/app.log"] }],
  });
  getLogsByPath.mockResolvedValue({
    entry: {},
    entries: [],
    more: false,
    lines: [failed, fine],
  });
  postRegex.mockResolvedValue({
    ok: true,
    output: "Lines: 2 lines, 0 ignored, 1 matched, 1 missed",
    summary: { lines: 2, ignored: 0, matched: 1, missed: 1 },
    lines: [
      { text: failed, verdict: "matched" },
      { text: fine, verdict: "missed" },
    ],
  });
  const onDraft = vi.fn();
  mount(
    <RegexTester
      file="app.local"
      content={"[Definition]\nfailregex = \n"}
      saved
      dirty={dirty}
      onDraft={onDraft}
    />,
  );
  return onDraft;
}

describe("the tester", () => {
  it("shows the log's lines, then what the filter made of each", async () => {
    tester();
    expect(await screen.findByText(fine)).toBeTruthy();
    expect(getLogsByPath).toHaveBeenCalledWith("/var/log/app.log", 2000);
    fireEvent.click(screen.getByRole("button", { name: "Run fail2ban-regex" }));
    const show = await screen.findByRole("group", { name: "Show" });
    fireEvent.click(within(show).getByRole("button", { name: /Matched/ }));
    await waitFor(() => expect(screen.queryByText(fine)).toBeNull());
    expect(screen.getByText(failed)).toBeTruthy();
  });

  it("starts a failregex from a line", async () => {
    const onDraft = tester();
    await screen.findByText(failed);
    fireEvent.click(
      screen.getAllByRole("button", {
        name: "Start a failregex from this line",
      })[0]!,
    );
    expect(onDraft).toHaveBeenCalledWith(
      "host app\\[\\d+\\]: login failed for <ADDR>",
    );
  });

  it("makes a jail reading the log with the filter", async () => {
    tester();
    await screen.findByText(failed);
    fireEvent.click(
      screen.getByRole("button", { name: "New jail for this filter…" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Open the jail" }),
    );
    await waitFor(() =>
      expect(window.location.pathname).toBe("/config/jails/app.local"),
    );
    const jail = seeded("jails", "app.local") ?? "";
    expect(jail).toMatch(/^filter +?= app$/m);
    expect(jail).toMatch(/^logpath +?= \/var\/log\/app\.log$/m);
  });

  it("asks for the filter saved before a jail names it", async () => {
    tester(true);
    const button = await screen.findByRole("button", {
      name: "New jail for this filter…",
    });
    expect((button as HTMLButtonElement).disabled).toBe(true);
  });
});
