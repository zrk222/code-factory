export const APPROVAL_POLICY_VERSION = "adversarial-approval.v1" as const;

export type ApprovalActionClass = "read" | "analyze" | "draft" | "code-change" | "external-send" | "deploy" | "delete" | "payment" | "credential";
export type ApprovalEnvironment = "test" | "production";
export type ApprovalVerdict = "auto-approved" | "human-required" | "denied";

export type ApprovalCheck = {
  id: string;
  passed: boolean;
  evidence: string;
};

export type ApprovalReviewInput = {
  actionDigest: string;
  boundActionDigest: string;
  actionClass: ApprovalActionClass;
  environment: ApprovalEnvironment;
  requestedBy: string;
  approvalAgentId: string;
  estimatedCostCents: number;
  hardBudgetCents: number;
  evidenceDigests: readonly string[];
  gates: readonly { kind: "deterministic" | "model"; status: "passed" | "warning" | "blocked"; evidenceClass: "proof-bearing" | "heuristic" }[];
};

export type ProofDelta = {
  reusedEvidence: string[];
  newEvidence: string[];
  missingEvidence: string[];
  reviewScope: "full" | "focused";
};

const AUTO_APPROVABLE_ACTIONS: readonly ApprovalActionClass[] = ["read", "analyze"];
const HIGH_IMPACT_ACTIONS: readonly ApprovalActionClass[] = ["code-change", "external-send", "deploy", "delete", "payment", "credential"];

function approvalChecks(input: ApprovalReviewInput): ApprovalCheck[] {
  const deterministic = input.gates.filter((gate) => gate.kind === "deterministic");
  return [
    { id: "action-digest-bound", passed: input.actionDigest === input.boundActionDigest, evidence: input.boundActionDigest },
    { id: "independent-reviewer", passed: input.requestedBy !== input.approvalAgentId, evidence: `${input.requestedBy} != ${input.approvalAgentId}` },
    { id: "budget-admitted", passed: Number.isInteger(input.estimatedCostCents) && input.estimatedCostCents >= 0 && input.estimatedCostCents <= input.hardBudgetCents, evidence: `${input.estimatedCostCents}/${input.hardBudgetCents} cents` },
    { id: "proof-bearing-gates", passed: deterministic.length >= 3 && deterministic.every((gate) => gate.status === "passed" && gate.evidenceClass === "proof-bearing"), evidence: `${deterministic.filter((gate) => gate.status === "passed").length}/${deterministic.length} deterministic gates passed` },
    { id: "evidence-bound", passed: input.evidenceDigests.length >= 2 && input.evidenceDigests.every((digest) => /^[a-f0-9]{16}$/i.test(digest)), evidence: `${input.evidenceDigests.length} bound evidence digests` },
    { id: "no-blocked-gate", passed: input.gates.every((gate) => gate.status !== "blocked"), evidence: `${input.gates.filter((gate) => gate.status === "blocked").length} blocked gates` },
  ];
}

const autoApprovalEligible = (input: ApprovalReviewInput): boolean =>
  input.environment === "test" && AUTO_APPROVABLE_ACTIONS.includes(input.actionClass) && input.estimatedCostCents <= 100;

const humanReason = (input: ApprovalReviewInput): string =>
  HIGH_IMPACT_ACTIONS.includes(input.actionClass) || input.environment === "production" ? "HUMAN_ACCOUNTABILITY_REQUIRED" : "POLICY_AUTO_APPROVAL_NOT_MET";

/** Narrows reviewer attention without carrying forward a prior decision or authority. */
export function compareProofEvidence(current: readonly string[], prior: readonly string[] | undefined): ProofDelta {
  const currentSet = new Set(current);
  const priorSet = new Set(prior ?? []);
  const reusedEvidence = [...currentSet].filter((digest) => priorSet.has(digest)).sort();
  const newEvidence = [...currentSet].filter((digest) => !priorSet.has(digest)).sort();
  const missingEvidence = [...priorSet].filter((digest) => !currentSet.has(digest)).sort();
  return {
    reusedEvidence,
    newEvidence,
    missingEvidence,
    reviewScope: priorSet.size > 0 && missingEvidence.length === 0 && reusedEvidence.length > 0 ? "focused" : "full",
  };
}

export function evaluateAdversarialApproval(input: ApprovalReviewInput): {
  marker: "ADVERSARIAL_APPROVAL_REVIEWED";
  policyVersion: typeof APPROVAL_POLICY_VERSION;
  verdict: ApprovalVerdict;
  reasonCodes: string[];
  checks: ApprovalCheck[];
} {
  const checks = approvalChecks(input);
  const failed = checks.filter((check) => !check.passed).map((check) => `E_${check.id.replaceAll("-", "_").toUpperCase()}`);
  if (failed.length > 0) return { marker: "ADVERSARIAL_APPROVAL_REVIEWED", policyVersion: APPROVAL_POLICY_VERSION, verdict: "denied", reasonCodes: failed, checks };
  if (autoApprovalEligible(input)) return { marker: "ADVERSARIAL_APPROVAL_REVIEWED", policyVersion: APPROVAL_POLICY_VERSION, verdict: "auto-approved", reasonCodes: ["SAFE_TEST_TASK_PROVED"], checks };
  return { marker: "ADVERSARIAL_APPROVAL_REVIEWED", policyVersion: APPROVAL_POLICY_VERSION, verdict: "human-required", reasonCodes: [humanReason(input)], checks };
}
