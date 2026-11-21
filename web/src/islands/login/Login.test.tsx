import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "@app/api/transport";
import { Login } from "@app/islands/login/Login";

const postAuthLogin = vi.fn();
const leaveFor = vi.fn();

vi.mock("@app/api/actions", () => ({
  postAuthLogin: (body: unknown) => postAuthLogin(body),
}));
vi.mock("@app/leave", () => ({ leaveFor: (path: string) => leaveFor(path) }));

afterEach(() => vi.clearAllMocks());

const type = (value: string) =>
  fireEvent.change(screen.getByLabelText("Password"), { target: { value } });

describe("signing in", () => {
  it("goes to the overview once the password matches", async () => {
    postAuthLogin.mockResolvedValue(undefined);
    render(<Login />);
    type("a good password");
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(leaveFor).toHaveBeenCalledWith("/"));
    expect(postAuthLogin).toHaveBeenCalledWith({ password: "a good password" });
  });

  it("says what the server said when it does not", async () => {
    postAuthLogin.mockRejectedValue(
      new ApiError(401, "unauthenticated", "That password is not the one."),
    );
    render(<Login />);
    type("not it");
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(
      await screen.findByText("That password is not the one."),
    ).toBeTruthy();
    expect(leaveFor).not.toHaveBeenCalled();
  });
});
