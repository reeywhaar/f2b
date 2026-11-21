import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Picker } from "@app/components/Picker";

const jails = Array.from({ length: 200 }, (_, i) => ({
  value: `jail-${i}`,
  label: `jail-${i}`,
}));

describe("the picker", () => {
  it("finds a choice by what is typed, and takes the first on Enter", () => {
    const onChange = vi.fn();
    render(
      <Picker
        label="Jail"
        value="jail-0"
        options={jails}
        onChange={onChange}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Jail: jail-0" }));
    const find = screen.getByLabelText("Find a jail");
    fireEvent.change(find, { target: { value: "199" } });
    expect(screen.getAllByRole("button", { name: /^jail-/ })).toHaveLength(1);
    fireEvent.keyDown(find, { key: "Enter" });
    expect(onChange).toHaveBeenCalledWith("jail-199");
  });

  it("says when nothing matches", () => {
    render(
      <Picker label="Jail" value="" options={jails} onChange={() => {}} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /^Jail:/ }));
    fireEvent.change(screen.getByLabelText("Find a jail"), {
      target: { value: "nope" },
    });
    expect(screen.getByText("Nothing by that name.")).toBeTruthy();
  });
});
