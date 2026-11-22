import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Segmented } from "@app/components/Segmented";

const options = [
  { value: "read", label: "Read" },
  { value: "write", label: "Read and write" },
] as const;

describe("a segmented control", () => {
  it("is a radio group, chosen by a press or by the arrows", () => {
    const onChange = vi.fn();
    render(
      <Segmented
        label="Can"
        value="read"
        options={options}
        onChange={onChange}
      />,
    );
    const read = screen.getByRole("radio", { name: "Read" });
    expect(read.getAttribute("aria-checked")).toBe("true");
    expect(read.tabIndex).toBe(0);
    expect(screen.getByRole("radio", { name: "Read and write" }).tabIndex).toBe(
      -1,
    );
    fireEvent.click(screen.getByRole("radio", { name: "Read and write" }));
    expect(onChange).toHaveBeenLastCalledWith("write");
    fireEvent.keyDown(read, { key: "ArrowLeft" });
    expect(onChange).toHaveBeenLastCalledWith("write");
    expect(document.activeElement?.textContent).toBe("Read and write");
  });
});
