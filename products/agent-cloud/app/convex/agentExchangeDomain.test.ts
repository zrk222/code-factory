import { describe, expect, test } from "vitest";
import {
  assertOutcomeTransition,
  buildOutcomeContract,
  outcomeAgentCatalog,
  outcomePaymentRails,
  verifyOutcomeEvidence,
} from "./agentExchangeDomain";

const humanHire = {
  workspaceId: "workspace-1",
  offerId: "pr-evidence-auditor",
  callerKind: "human" as const,
  intentRef: "repo://org/project/pull/42",
  intentDigest: "a".repeat(64),
  delegationDepth: 0,
  idempotencyKey: "hire-pr-42",
  createdAt: 1_800_000_000_000,
};

describe("Outcome Agent Exchange domain", () => {
  test("publishes six fixed-price, evidence-bound offers and four rails", () => {
    expect(outcomeAgentCatalog).toHaveLength(6);
    expect(new Set(outcomeAgentCatalog.map((offer) => offer.id)).size).toBe(6);
    expect(outcomeAgentCatalog.every((offer) => offer.evidenceChecks.length === 4)).toBe(true);
    expect(outcomePaymentRails.map((rail) => rail.status)).toEqual(["active", "setup-required", "setup-required", "setup-required"]);
  });

  test("seals the same hire input to the same immutable contract", () => {
    const first = buildOutcomeContract(humanHire);
    const second = buildOutcomeContract(humanHire);
    expect(first.contractDigest).toBe(second.contractDigest);
    expect(first.offer.resultCredits).toBe(90);
    expect(first.canonical).toContain('"schema":"agent-oven.outcome-contract.v1"');
  });

  test("requires a mandate and agent id for an agent caller", () => {
    expect(() => buildOutcomeContract({ ...humanHire, callerKind: "agent" })).toThrow("E_INVALID_CALLER_AGENT_ID");
    expect(() => buildOutcomeContract({ ...humanHire, callerKind: "agent", callerAgentId: "agent://buyer" })).toThrow("E_INVALID_MANDATE_DIGEST");
    expect(buildOutcomeContract({ ...humanHire, callerKind: "agent", callerAgentId: "agent://buyer", mandateDigest: "m".repeat(64), delegationDepth: 1 }).offer.id).toBe("pr-evidence-auditor");
  });

  test("blocks recursive delegation beyond one hop", () => {
    expect(() => buildOutcomeContract({ ...humanHire, delegationDepth: 2 })).toThrow("E_DELEGATION_DEPTH_EXCEEDED");
  });

  test("passes only an exact set of passing digest-bound evidence", () => {
    const offer = outcomeAgentCatalog[0];
    const items = offer.evidenceChecks.map((check) => ({ checkId: check.id, artifactRef: `artifact://${check.id}`, artifactDigest: check.id.padEnd(64, "0"), status: "passed" as const }));
    const result = verifyOutcomeEvidence(offer.evidenceChecks.map((check) => check.id), items);
    expect(result.marker).toBe("OUTCOME_EVIDENCE_VERIFIED");
    expect(result.items).toHaveLength(4);
    expect(() => verifyOutcomeEvidence(offer.evidenceChecks.map((check) => check.id), items.slice(1))).toThrow("E_OUTCOME_EVIDENCE_INCOMPLETE");
    expect(() => verifyOutcomeEvidence(offer.evidenceChecks.map((check) => check.id), items.map((item, index) => index === 0 ? { ...item, status: "failed" as const } : item))).toThrow("E_OUTCOME_EVIDENCE_FAILED");
  });

  test("enforces the contract state machine", () => {
    expect(() => assertOutcomeTransition("accepted", "running")).not.toThrow();
    expect(() => assertOutcomeTransition("running", "paid")).toThrow("E_OUTCOME_TRANSITION_INVALID");
    expect(() => assertOutcomeTransition("paid", "canceled")).toThrow("E_OUTCOME_TRANSITION_INVALID");
  });
});
