import { describe, expect, test } from "vitest";
import { businessTemplates } from "./templates";

describe("boring business template contract", () => {
  test("ships a complete and uniquely-addressable recipe library", () => {
    expect(businessTemplates.length).toBeGreaterThanOrEqual(18);
    expect(new Set(businessTemplates.map((item) => item.id)).size).toBe(businessTemplates.length);
    for (const template of businessTemplates) {
      expect(template.loop.length).toBeGreaterThanOrEqual(3);
      expect(template.loop.length).toBeLessThanOrEqual(5);
      expect(template.inputs.length).toBeGreaterThan(0);
      expect(template.integrations.length).toBeGreaterThan(0);
      expect(template.hardBudgetDollars).toBeGreaterThan(0);
      expect(["Standard", "Premium trust"]).toContain(template.tier);
    }
  });

  test("governs regulated recipes with approval gates and explicit boundaries", () => {
    const regulated = businessTemplates.filter((item) => item.regulatedDomain);
    expect(regulated.length).toBeGreaterThanOrEqual(5);
    expect(regulated.every((item) => item.tier === "Premium trust")).toBe(true);
    expect(regulated.every((item) => item.authority !== "read-only")).toBe(true);
    expect(regulated.every((item) => (item.guardrails?.length ?? 0) >= 3)).toBe(true);
  });

  test("makes legal, MLS, and civic-planning evidence boundaries explicit", () => {
    const legal = businessTemplates.find((item) => item.id === "legal-research-workbench");
    const mls = businessTemplates.find((item) => item.id === "broker-mls-intelligence");
    const consumer = businessTemplates.find((item) => item.id === "homebuyer-seller-guide");
    const civic = businessTemplates.find((item) => item.id === "civic-planning-intelligence");
    expect(legal?.sourcePolicy).toContain("effective date");
    expect(legal?.guardrails?.join(" ")).toContain("lawyer approval");
    expect(mls?.sourcePolicy).toContain("permitted-use class");
    expect(mls?.guardrails?.join(" ")).toContain("No steering");
    expect(consumer?.category).toBe("B2C");
    expect(consumer?.authority).toBe("propose");
    expect(consumer?.guardrails?.join(" ")).toContain("Does not act as a broker");
    expect(civic?.sourcePolicy).toContain("amendment chain");
    expect(civic?.guardrails?.join(" ")).toContain("unknown or conflict");
  });

  test("reserves long-term governed memory for every premium trust recipe", () => {
    const premium = businessTemplates.filter((item) => item.tier === "Premium trust");
    expect(premium.length).toBeGreaterThanOrEqual(5);
    expect(premium.every((item) => item.memory === "architecture-history")).toBe(true);
  });
});
