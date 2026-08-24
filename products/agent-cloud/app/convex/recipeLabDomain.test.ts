import { describe, expect, test } from "vitest";
import { evaluateRecipeEligibility, generateRecipeCandidates, selectRecipeChampion } from "./recipeLabDomain";

describe("recipe lab domain", () => {
  test("generates deterministic bounded candidates", () => {
    const input = { trialCount: 4, models: ["openai/gpt-5", "anthropic/claude"], retrievalTopK: [4, 8], memoryModes: ["run-only"] as const, authorityModes: ["read-only", "approval-required"] as const };
    expect(generateRecipeCandidates(input)).toEqual(generateRecipeCandidates(input));
    expect(generateRecipeCandidates(input)).toHaveLength(4);
    expect(() => generateRecipeCandidates({ ...input, trialCount: 24, models: ["one"] })).toThrow("E_RECIPE_SEARCH_SPACE_INVALID");
  });

  test("makes policy violations ineligible and selects a Pareto champion", () => {
    const constraints = { minQuality: 70, maxLatencyMs: 30000, perTrialCreditCap: 100 };
    expect(evaluateRecipeEligibility({ recipeDigest: "unsafe", qualityScore: 99, costCredits: 1, latencyMs: 1, policyViolations: 1 }, constraints).eligible).toBe(false);
    const result = selectRecipeChampion([
      { recipeDigest: "quality", qualityScore: 95, costCredits: 90, latencyMs: 20000, policyViolations: 0 },
      { recipeDigest: "balanced", qualityScore: 90, costCredits: 30, latencyMs: 7000, policyViolations: 0 },
      { recipeDigest: "dominated", qualityScore: 80, costCredits: 50, latencyMs: 9000, policyViolations: 0 },
    ], constraints, { quality: 50, cost: 30, latency: 20 });
    expect(result.frontier.map((item) => item.recipeDigest)).toEqual(["quality", "balanced"]);
    expect(result.champion?.recipeDigest).toBe("balanced");
  });
});
