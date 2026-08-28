import { describe, expect, test } from "vitest";
import { businessTemplates } from "./templates";
import { opportunityScore, rankedRegulatedOpportunities, regulatedOpportunities } from "./regulatedOpportunities";

describe("regulated opportunity registry", () => {
  test("maps every opportunity to a premium governed template", () => {
    for (const opportunity of regulatedOpportunities) {
      const template = businessTemplates.find((candidate) => candidate.id === opportunity.templateId);
      expect(template, opportunity.templateId).toBeDefined();
      expect(template?.tier).toBe("Premium trust");
      expect(template?.memory).toBe("architecture-history");
      expect(template?.sourcePolicy).toBeTruthy();
      expect(template?.guardrails?.length).toBeGreaterThanOrEqual(3);
    }
  });

  test("uses bounded evidence-weighted scoring with deterministic ranking", () => {
    const ranked = rankedRegulatedOpportunities();
    expect(ranked).toHaveLength(regulatedOpportunities.length);
    expect(new Set(ranked.map((item) => item.id)).size).toBe(ranked.length);
    expect(ranked.every((item, index) => index === 0 || opportunityScore(ranked[index - 1]) >= opportunityScore(item))).toBe(true);
    expect(ranked.every((item) => item.sourceClasses.length >= 4)).toBe(true);
    expect(ranked.every((item) => item.accountableOwner.length > 0)).toBe(true);
  });
});
