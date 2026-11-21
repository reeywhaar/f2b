import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Session } from "@app/islands/app/Session";
import { mount } from "@app/test/harness";

const postAuthLogout = vi.fn();
const postAuthLogoutEverywhere = vi.fn();
const leaveFor = vi.fn();

vi.mock("@app/api/actions", () => ({
  postAuthLogout: () => postAuthLogout(),
  postAuthLogoutEverywhere: () => postAuthLogoutEverywhere(),
}));
vi.mock("@app/leave", () => ({ leaveFor: (p: string) => leaveFor(p) }));

afterEach(() => vi.clearAllMocks());

describe("signing out", () => {
  it("signs this browser out at once", async () => {
    postAuthLogout.mockResolvedValue(undefined);
    mount(<Session />);
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(leaveFor).toHaveBeenCalledWith("/login"));
    expect(postAuthLogoutEverywhere).not.toHaveBeenCalled();
  });

  it("asks before signing every browser out", async () => {
    postAuthLogoutEverywhere.mockResolvedValue(undefined);
    mount(<Session />);
    fireEvent.click(
      screen.getByRole("button", { name: "Sign out everywhere…" }),
    );
    expect(postAuthLogoutEverywhere).not.toHaveBeenCalled();
    fireEvent.click(
      await screen.findByRole("button", { name: "Sign out everywhere" }),
    );
    await waitFor(() => expect(leaveFor).toHaveBeenCalledWith("/login"));
  });
});
