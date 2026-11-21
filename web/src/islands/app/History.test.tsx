import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { History } from "@app/islands/app/History";
import { mount } from "@app/test/harness";

const go = vi.fn();

vi.mock("@app/api/actions", () => ({
  getHistory: async () => ({ bans: [], next: 0 }),
  getJails: async () => ({ jails: [] }),
  getStats: async () => ({ jails: ["sshd"] }),
}));

vi.mock("@app/islands/app/route", async (actual) => ({
  ...(await actual<typeof import("@app/islands/app/route")>()),
  go: (...a: unknown[]) => go(...a),
}));

afterEach(() => vi.clearAllMocks());

describe("narrowing the history", () => {
  it("applies an address once typing pauses, with no button to press", async () => {
    mount(<History jail="" ip="" />);
    fireEvent.change(screen.getByLabelText("Only the bans of this address"), {
      target: { value: "203.0.113.7" },
    });
    expect(go).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(go).toHaveBeenCalledWith("/history?ip=203.0.113.7", true),
    );
    expect(screen.queryByRole("button", { name: "Show" })).toBeNull();
  });

  it("shows everything again the moment the address is cleared", async () => {
    mount(<History jail="sshd" ip="203.0.113.7" />);
    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(go).toHaveBeenCalledWith("/history?jail=sshd", true);
  });
});
