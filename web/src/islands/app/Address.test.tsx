import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Address } from "@app/islands/app/Address";

const go = vi.fn();

vi.mock("@app/islands/app/route", async (actual) => ({
  ...(await actual<typeof import("@app/islands/app/route")>()),
  go: (...a: unknown[]) => go(...a),
}));

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe("an address", () => {
  it("copies itself, and says so", async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    render(<Address ip="203.0.113.7" href="/history?ip=203.0.113.7" />);
    fireEvent.click(screen.getByRole("button", { name: "Copy 203.0.113.7" }));
    expect(writeText).toHaveBeenCalledWith("203.0.113.7");
    expect(
      await screen.findByRole("button", { name: "Copied 203.0.113.7" }),
    ).toBeTruthy();
  });

  it("is a link, which narrows in place when asked to", () => {
    render(<Address ip="203.0.113.7" href="/history?ip=203.0.113.7" replace />);
    const link = screen.getByRole("link", { name: "203.0.113.7" });
    expect(link.getAttribute("href")).toBe("/history?ip=203.0.113.7");
    fireEvent.click(link);
    expect(go).toHaveBeenCalledWith("/history?ip=203.0.113.7", true);
  });

  it("has no copy button where the browser has no clipboard", () => {
    vi.stubGlobal("navigator", {});
    render(<Address ip="203.0.113.7" href="/history?ip=203.0.113.7" />);
    expect(screen.queryByRole("button")).toBeNull();
  });
});
