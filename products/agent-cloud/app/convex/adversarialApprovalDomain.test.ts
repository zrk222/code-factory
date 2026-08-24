import { describe, expect, test } from "vitest";
import { compareProofEvidence, evaluateAdversarialApproval, type ApprovalReviewInput } from "./adversarialApprovalDomain";

const evidence = ["0123456789abcdef", "fedcba9876543210"];
const gates: ApprovalReviewInput["gates"] = [
  { kind: "deterministic", status: "passed", evidenceClass: "proof-bearing" },
  { kind: "deterministic", status: "passed", evidenceClass: "proof-bearing" },
  { kind: "deterministic", status: "passed", evidenceClass: "proof-bearing" },
  { kind: "model", status: "warning", evidenceClass: "heuristic" },
];

function review(overrides: Partial<ApprovalReviewInput> = {}) {
  return evaluateAdversarialApproval({
    actionDigest: "digest",
    boundActionDigest: "digest",
    actionClass: "analyze",
    environment: "test",
    requestedBy: "worker-agent",
    approvalAgentId: "approval-agent",
    estimatedCostCents: 50,
    hardBudgetCents: 100,
    evidenceDigests: evidence,
    gates,
    ...overrides,
  });
}

describe("adversarial approval policy", () => {
  test("auto-approves only proved low-cost analysis in test", () => {
    expect(review()).toMatchObject({ verdict: "auto-approved", reasonCodes: ["SAFE_TEST_TASK_PROVED"] });
  });

  test("forces a human for code changes and production", () => {
    expect(review({ actionClass: "code-change", environment: "production" })).toMatchObject({ verdict: "human-required", reasonCodes: ["HUMAN_ACCOUNTABILITY_REQUIRED"] });
  });

  test("denies identity collision and stale evidence shape", () => {
    const result = review({ requestedBy: "approval-agent", evidenceDigests: ["not-a-digest"] });
    expect(result.verdict).toBe("denied");
    expect(result.reasonCodes).toEqual(expect.arrayContaining(["E_INDEPENDENT_REVIEWER", "E_EVIDENCE_BOUND"]));
  });

  test("focuses review on proof deltas without inheriting a decision", () => {
    expect(compareProofEvidence(["a", "b", "c"], ["a", "b"])).toEqual({ reusedEvidence: ["a", "b"], newEvidence: ["c"], missingEvidence: [], reviewScope: "focused" });
    expect(compareProofEvidence(["a"], ["a", "b"]).reviewScope).toBe("full");
  });
});
