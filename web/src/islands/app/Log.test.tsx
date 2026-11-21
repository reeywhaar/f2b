import { screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "@app/api/transport";
import { Log } from "@app/islands/app/Log";
import { mount } from "@app/test/harness";

const getLog = vi.fn();

vi.mock("@app/api/actions", () => ({
  getLog: (...args: unknown[]) => getLog(...args),
}));

describe("the log", () => {
  // In braces: a function returned from beforeEach is run as the test's cleanup, and mockReset
  // returns the mock.
  beforeEach(() => {
    getLog.mockReset();
  });

  it("says nothing is logged only once the engine has said so", async () => {
    getLog.mockResolvedValue({ epoch: "e1", last: 0, lines: [] });
    mount(<Log />);
    expect(screen.queryByText("Nothing logged yet.")).toBeNull();
    expect(await screen.findByText("Nothing logged yet.")).toBeTruthy();
  });

  it("does not call a log it could not read empty", async () => {
    getLog.mockImplementation(async () => {
      throw new ApiError(0, "network", "The server could not be reached.");
    });
    mount(<Log />);
    expect(
      await screen.findByText("The server could not be reached."),
    ).toBeTruthy();
    expect(screen.queryByText("Nothing logged yet.")).toBeNull();
  });
});
