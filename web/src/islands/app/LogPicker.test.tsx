import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Jail, LogEntry } from "@app/api/types";
import { LogPicker, PASTED } from "@app/islands/app/LogPicker";
import { mount } from "@app/test/harness";

const getLogs = vi.fn();
const getLogsByPath = vi.fn();
const getLogFiles = vi.fn();

vi.mock("@app/api/actions", () => ({
  getLogs: () => getLogs(),
  getLogsByPath: (p: string) => getLogsByPath(p),
  getLogFiles: () => getLogFiles(),
}));

afterEach(async () => {
  vi.clearAllMocks();
  // A close takes the picker's steps back off the history a moment later, and one left open
  // leaves its steps there: either would land in the next test, on its picker.
  await new Promise((r) => setTimeout(r, 20));
  const left = window.history.state?.f2bLogPicker;
  if (left) window.history.go(-left);
  await waitFor(() =>
    expect(window.history.state?.f2bLogPicker).toBeUndefined(),
  );
});

const jail = (name: string, logs: string[]): Jail =>
  ({ name, logs, filter: name }) as Jail;
const jails = [
  jail("sshd", ["/var/log/auth.log"]),
  jail("mailio", ["/remotelogs/mailio.log"]),
];
const entry = (path: string, dir = false): LogEntry => ({
  name: path.split("/").pop() ?? path,
  path,
  dir,
  size: dir ? 0 : 2048,
  modified: Math.floor(Date.now() / 1000) - 60,
  jails: [],
});

function open(value = "/var/log/auth.log") {
  const onChange = vi.fn();
  getLogs.mockResolvedValue({
    roots: [{ ...entry("/var/log", true), source: "mount" }],
  });
  mount(<LogPicker value={value} onChange={onChange} jails={jails} />);
  fireEvent.click(screen.getByRole("button", { name: /^Lines from/ }));
  return onChange;
}

describe("the log picker", () => {
  it("says which jails read the log it is on", () => {
    open();
    expect(
      screen.getAllByText((_, el) => el?.textContent === " · sshd").length,
    ).toBeGreaterThan(0);
  });

  it("finds a jail's log by the jail's name, and takes it on Enter", async () => {
    const onChange = open();
    const find = screen.getByLabelText("Find a log or a jail, or type a path");
    fireEvent.change(find, { target: { value: "mail" } });
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).queryByText("/var/log/auth.log")).toBeNull();
    expect(within(dialog).getByText("/remotelogs/mailio.log")).toBeTruthy();
    fireEvent.keyDown(find, { key: "Enter" });
    expect(onChange).toHaveBeenCalledWith("/remotelogs/mailio.log");
  });

  it("goes through a directory to a file in it", async () => {
    getLogsByPath.mockImplementation(async (p: string) =>
      p === "/var/log"
        ? {
            entry: entry("/var/log", true),
            entries: [entry("/var/log/nginx", true), entry("/var/log/syslog")],
            more: false,
          }
        : {
            entry: entry(p, true),
            entries: [entry("/var/log/nginx/access.log.1.gz")],
            more: false,
          },
    );
    const onChange = open();
    fireEvent.click(await screen.findByText("/var/log"));
    fireEvent.click(await screen.findByText("nginx"));
    expect(await screen.findByText("access.log.1.gz")).toBeTruthy();
    // Back up a step by the crumbs.
    fireEvent.click(screen.getByRole("button", { name: "/var/log" }));
    fireEvent.click(await screen.findByText("syslog"));
    expect(onChange).toHaveBeenCalledWith("/var/log/syslog");
    expect(getLogsByPath).toHaveBeenCalledWith("/var/log/nginx");
  });

  it("finds a file in a directory under the places by its name", async () => {
    getLogFiles.mockResolvedValue({
      roots: [],
      files: [
        entry("/var/log/auth.log"),
        entry("/var/log/backup/restic.log"),
        entry("/var/log/syslog"),
      ],
      more: false,
    });
    const onChange = open();
    const find = screen.getByLabelText("Find a log or a jail, or type a path");
    fireEvent.change(find, { target: { value: "res" } });
    expect(await screen.findByText("/var/log/backup/restic.log")).toBeTruthy();
    expect(screen.queryByText("/var/log/syslog")).toBeNull();
    fireEvent.keyDown(find, { key: "Enter" });
    expect(onChange).toHaveBeenCalledWith("/var/log/backup/restic.log");
  });

  it("finds what is under the directory it is in", async () => {
    getLogFiles.mockResolvedValue({
      roots: [],
      files: [entry("/var/log/backup/restic.log"), entry("/srv/restic.log")],
      more: false,
    });
    getLogsByPath.mockResolvedValue({
      entry: entry("/var/log", true),
      entries: [entry("/var/log/backup", true)],
      more: false,
    });
    const onChange = open();
    fireEvent.click(await screen.findByText("/var/log"));
    const find = await screen.findByLabelText(
      "Find in this directory and under it",
    );
    fireEvent.change(find, { target: { value: "restic" } });
    expect(await screen.findByText("backup/restic.log")).toBeTruthy();
    expect(screen.queryByText("/srv/restic.log")).toBeNull();
    fireEvent.keyDown(find, { key: "Enter" });
    expect(onChange).toHaveBeenCalledWith("/var/log/backup/restic.log");
  });

  it("goes up a directory on the browser's Back, and out of the dialog from the top", async () => {
    getLogsByPath.mockImplementation(async (p: string) =>
      p === "/var/log"
        ? {
            entry: entry("/var/log", true),
            entries: [entry("/var/log/nginx", true), entry("/var/log/syslog")],
            more: false,
          }
        : {
            entry: entry(p, true),
            entries: [entry("/var/log/nginx/access.log")],
            more: false,
          },
    );
    const page = window.location.pathname;
    open();
    fireEvent.click(await screen.findByText("/var/log"));
    fireEvent.click(await screen.findByText("nginx"));
    expect(await screen.findByText("access.log")).toBeTruthy();

    window.history.back();
    expect(await screen.findByText("syslog")).toBeTruthy();
    window.history.back();
    expect(await screen.findByText("Log directories")).toBeTruthy();
    window.history.back();
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(window.location.pathname).toBe(page);
  });

  it("closed another way, takes its steps back off", async () => {
    getLogsByPath.mockResolvedValue({
      entry: entry("/var/log", true),
      entries: [entry("/var/log/syslog")],
      more: false,
    });
    open();
    fireEvent.click(await screen.findByText("/var/log"));
    await screen.findByText("syslog");
    expect(window.history.state?.f2bLogPicker).toBe(2);
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await waitFor(() =>
      expect(window.history.state?.f2bLogPicker).toBeUndefined(),
    );
  });

  it("takes a path typed, or lines pasted", async () => {
    const onChange = open();
    const find = screen.getByLabelText("Find a log or a jail, or type a path");
    fireEvent.change(find, { target: { value: "/srv/app.log" } });
    fireEvent.keyDown(find, { key: "Enter" });
    expect(onChange).toHaveBeenCalledWith("/srv/app.log");

    fireEvent.click(screen.getByRole("button", { name: /^Lines from/ }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Lines pasted here" }),
    );
    await waitFor(() => expect(onChange).toHaveBeenLastCalledWith(PASTED));
  });
});
