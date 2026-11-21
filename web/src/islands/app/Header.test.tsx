import { screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Header } from "@app/islands/app/Header";
import { mount } from "@app/test/harness";

vi.mock("@app/api/actions", () => ({
  getAuthMe: async () => ({ ok: true, version: "dev", label: "hellogram" }),
  getEngine: async () => ({
    version: "dev",
    fail2ban: {
      state: "running",
      version: "1.1.0",
      pid: 7,
      since: Date.now() / 1000 - 3600,
      restarts: 0,
      lastExit: "",
    },
  }),
  postAuthLogout: vi.fn(),
  postAuthLogoutEverywhere: vi.fn(),
}));

describe("the header", () => {
  it("has one way to the log, which says how fail2ban is doing", async () => {
    mount(<Header route={{ page: "overview", days: 30 }} />);
    await waitFor(() =>
      expect(
        screen.getByRole("link", { name: /fail2ban 1\.1\.0 running.*Log/ }),
      ).toBeTruthy(),
    );
    const toLog = screen
      .getAllByRole("link")
      .filter((a) => a.getAttribute("href") === "/log");
    expect(toLog).toHaveLength(1);
  });

  it("names the server, in the header and the tab", async () => {
    mount(<Header route={{ page: "overview", days: 30 }} />);
    expect(await screen.findByText("hellogram")).toBeTruthy();
    await waitFor(() => expect(document.title).toBe("hellogram · f2b"));
  });

  it("goes to Config by the server's name, and marks it while there", async () => {
    mount(
      <Header
        route={{ page: "file", kind: "jails", name: "x.local", fresh: false }}
      />,
    );
    const config = await screen.findByRole("link", {
      name: "hellogram: Config",
    });
    expect(config.getAttribute("href")).toBe("/config");
    expect(config.getAttribute("aria-current")).toBe("page");
    const nav = screen.getByRole("navigation");
    expect(nav.querySelector('a[href="/config"]')).toBeNull();
  });
});
