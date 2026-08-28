import { describe, expect, test } from "vitest";
import { regulatedOpportunities } from "./regulatedOpportunities";
import { automationPackFor, templateAutomationPacks } from "./templateAutomationPacks";

describe("novice regulated automation packs", () => {
  test("covers every ranked regulated opportunity", () => {
    for (const opportunity of regulatedOpportunities) {
      const pack = automationPackFor(opportunity.templateId);
      expect(pack, opportunity.templateId).toBeDefined();
      expect(pack?.setupQuestions.length).toBeGreaterThanOrEqual(4);
      expect(pack?.automations.length).toBeGreaterThanOrEqual(2);
    }
  });

  test("makes every automation bounded and human-owned", () => {
    expect(new Set(templateAutomationPacks.map((pack) => pack.templateId)).size).toBe(templateAutomationPacks.length);
    for (const pack of templateAutomationPacks) {
      for (const automation of pack.automations) {
        expect(automation.steps.length).toBeGreaterThanOrEqual(4);
        expect(automation.approval.length).toBeGreaterThan(0);
        expect(automation.result.length).toBeGreaterThan(0);
        expect(automation.stopIf.length).toBeGreaterThanOrEqual(3);
      }
    }
  });
});
