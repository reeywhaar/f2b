import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Token } from "@app/api/types";
import { Tokens } from "@app/islands/app/Tokens";
import { mount } from "@app/test/harness";

const now = Math.floor(Date.now() / 1000);
const agent: Token = {
  id: "a1b2c3d4e5f60718",
  name: "agent",
  scope: "read",
  created: now - 3 * 86400,
  lastUsed: now - 120,
  expires: now + 87 * 86400,
  idle: 30 * 86400,
  ends: now + 30 * 86400,
  expired: false,
};

const getAuthTokens = vi.fn();
const postAuthTokens = vi.fn();
const deleteAuthTokensById = vi.fn();

vi.mock("@app/api/actions", () => ({
  getAuthTokens: () => getAuthTokens(),
  postAuthTokens: (b: unknown) => postAuthTokens(b),
  deleteAuthTokensById: (id: string) => deleteAuthTokensById(id),
}));

afterEach(() => vi.clearAllMocks());

describe("API tokens", () => {
  it("lists each with what it can do and how long it lasts", async () => {
    getAuthTokens.mockResolvedValue({ tokens: [agent] });
    mount(<Tokens />);
    expect(await screen.findByText("agent")).toBeTruthy();
    expect(screen.getByText("reads")).toBeTruthy();
    expect(screen.getByText(/never used|used 2m ago/)).toBeTruthy();
    expect(screen.getByText(/lasts 90 days, and 30 days unused/)).toBeTruthy();
  });

  it("issues one, and shows it this once", async () => {
    getAuthTokens.mockResolvedValue({ tokens: [] });
    postAuthTokens.mockResolvedValue({
      token: { ...agent, name: "ci" },
      secret: "f2b_a1b2c3d4e5f60718_secret",
    });
    mount(<Tokens />);
    fireEvent.click(await screen.findByRole("button", { name: "New token…" }));
    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: " ci " },
    });
    fireEvent.change(screen.getByLabelText("Can"), {
      target: { value: "write" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Issue" }));
    await waitFor(() =>
      expect(postAuthTokens).toHaveBeenCalledWith({
        name: "ci",
        scope: "write",
        expiresIn: "90d",
        idleFor: "30d",
      }),
    );
    expect(await screen.findByText("f2b_a1b2c3d4e5f60718_secret")).toBeTruthy();
    expect(screen.getByText(/the only time it is shown/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() =>
      expect(screen.queryByText("f2b_a1b2c3d4e5f60718_secret")).toBeNull(),
    );
  });

  it("asks before revoking one", async () => {
    getAuthTokens.mockResolvedValue({ tokens: [agent] });
    deleteAuthTokensById.mockResolvedValue(undefined);
    mount(<Tokens />);
    fireEvent.click(await screen.findByRole("button", { name: "Revoke…" }));
    expect(deleteAuthTokensById).not.toHaveBeenCalled();
    fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
    await waitFor(() =>
      expect(deleteAuthTokensById).toHaveBeenCalledWith(agent.id),
    );
  });
});
