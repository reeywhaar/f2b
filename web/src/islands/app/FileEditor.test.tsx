import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "@app/api/transport";
import { FileEditor } from "@app/islands/app/FileEditor";
import { mount } from "@app/test/harness";

const putFile = vi.fn();
const getFile = vi.fn();

vi.mock("@app/api/actions", () => ({
  getFile: (...a: unknown[]) => getFile(...a),
  putFile: (...a: unknown[]) => putFile(...a),
  getStock: async () => ({ filters: [], actions: [], other: [] }),
  getJails: async () => ({ jails: [] }),
  postCheck: vi.fn(),
  postRegex: vi.fn(),
  deleteFile: vi.fn(),
}));

/** The editor stands in as a textarea: what it is fed and what it reports are what matter here. */
vi.mock("@app/editor/CodeEditor", () => ({
  CodeEditor: (p: {
    value: string;
    onChange?: (v: string) => void;
    label: string;
  }) => (
    <textarea
      aria-label={p.label}
      value={p.value}
      onChange={(e) => p.onChange?.(e.target.value)}
    />
  ),
}));

const file = {
  kind: "filters" as const,
  name: "app.local",
  size: 10,
  modified: 0,
  version: "v1",
  sections: ["Definition"],
};

afterEach(() => vi.clearAllMocks());

describe("saving a file", () => {
  it("sends what was typed against the version it was opened at", async () => {
    getFile.mockResolvedValue({ file, content: "[Definition]\n" });
    putFile.mockResolvedValue({
      file: { ...file, version: "v2" },
      reload: { ok: true, output: "OK" },
    });
    mount(<FileEditor kind="filters" name="app.local" fresh={false} />);
    const editor = await screen.findByLabelText("app.local, editable");
    fireEvent.change(editor, {
      target: { value: "[Definition]\nfailregex = x <ADDR>\n" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(
      await screen.findByText("Saved, and fail2ban reloaded with it."),
    ).toBeTruthy();
    expect(putFile).toHaveBeenCalledWith("filters", "app.local", {
      content: "[Definition]\nfailregex = x <ADDR>\n",
      version: "v1",
    });
  });

  it("shows fail2ban's own words when it refuses, and keeps what was typed", async () => {
    getFile.mockResolvedValue({ file, content: "[Definition]\n" });
    putFile.mockRejectedValue(
      new ApiError(
        422,
        "config_rejected",
        "fail2ban refused this configuration, and nothing was saved.",
        "ERROR: No failure-regex is present",
      ),
    );
    mount(<FileEditor kind="filters" name="app.local" fresh={false} />);
    const editor = await screen.findByLabelText("app.local, editable");
    fireEvent.change(editor, { target: { value: "broken" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(
      await screen.findByText("ERROR: No failure-regex is present"),
    ).toBeTruthy();
    expect(
      (screen.getByLabelText("app.local, editable") as HTMLTextAreaElement)
        .value,
    ).toBe("broken");
  });

  it("offers to open the file again when it changed on disk", async () => {
    getFile.mockResolvedValue({ file, content: "[Definition]\n" });
    putFile.mockRejectedValue(
      new ApiError(409, "conflict", "That file changed since it was opened."),
    );
    mount(<FileEditor kind="filters" name="app.local" fresh={false} />);
    fireEvent.change(await screen.findByLabelText("app.local, editable"), {
      target: { value: "mine" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Open it again…" }),
      ).toBeTruthy(),
    );
  });

  it("starts a new file from its kind's template, and saves it as new", async () => {
    putFile.mockResolvedValue({
      file: { ...file, kind: "jails", name: "web.local" },
      reload: { ok: true, output: "OK" },
    });
    mount(<FileEditor kind="jails" name="web.local" fresh />);
    const editor = (await screen.findByLabelText(
      "web.local, editable",
    )) as HTMLTextAreaElement;
    expect(editor.value).toContain(
      "[web]\nenabled   = true\nfilter    = web\n",
    );
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(putFile).toHaveBeenCalledWith(
        "jails",
        "web.local",
        expect.objectContaining({ version: "" }),
      ),
    );
    expect(getFile).not.toHaveBeenCalled();
  });
});
