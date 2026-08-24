import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, test, vi } from "vitest";
import axe from "axe-core";
import { TemplateCatalog } from "./TemplateCatalog";

describe("TemplateCatalog regulated novice journey", () => {
  test("explains a preset automation before applying safe defaults", async () => {
    const onApply = vi.fn();
    const { container } = render(<TemplateCatalog onApply={onApply} />);

    expect(screen.getByText("28 launch recipes")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Trade Compliance Command/i }));
    expect(screen.getByText(/Each screen records exact party inputs/i)).toBeInTheDocument();
    expect(screen.getByText(/A fuzzy match is a review signal/i)).toBeInTheDocument();

    await userEvent.click(screen.getByText("Included automations"));
    expect(screen.getByText("Check a new trading party")).toBeInTheDocument();
    expect(screen.getAllByText((_, element) => element?.textContent === "Human decision: Trade compliance officer").length).toBeGreaterThan(0);
    expect(screen.getByText(/Stops for Identity cannot be resolved/i)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /Use this recipe/i }));
    expect(onApply).toHaveBeenCalledWith(expect.objectContaining({ id: "trade-compliance-command", authority: "approval-required" }));

    const accessibility = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(accessibility.violations).toEqual([]);
  });
});
