import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";

const hireArgs = (workspaceId: string) => ({
  workspaceId: workspaceId as never,
  offerId: "pr-evidence-auditor",
  callerKind: "human" as const,
  intentRef: "repo://org/project/pull/42",
  intentDigest: "a".repeat(64),
  delegationDepth: 0,
  idempotencyKey: "hire-pr-42",
});

const proofItems = ["requirements-bound", "negative-proof", "artifact-digests", "scope-reviewed"].map((checkId) => ({
  checkId,
  artifactRef: `artifact://${checkId}`,
  artifactDigest: checkId.padEnd(64, "0"),
  status: "passed" as const,
}));

describe("Outcome Agent Exchange API", () => {
  test("hires once, verifies independently, and settles the fixed result price once", async () => {
    const t = authenticatedTest("buyer-owner");
    const seed = await t.mutation(api.seed.ensureDemo, {});
    const hired = await t.mutation(api.agentExchange.hire, hireArgs(String(seed.workspaceId)));
    expect(hired).toMatchObject({ marker: "OUTCOME_AGENT_HIRED", resultCredits: 90, state: "accepted" });
    const replay = await t.mutation(api.agentExchange.hire, hireArgs(String(seed.workspaceId)));
    expect(replay.marker).toBe("OUTCOME_IDEMPOTENCY_REPLAY");
    expect((await t.query(api.credits.status, { workspaceId: seed.workspaceId })).account).toMatchObject({ availableCredits: 410, reservedCredits: 90 });

    await t.mutation(api.agentExchange.start, { contractId: hired.contractId });
    await t.mutation(api.agentExchange.submitEvidence, { contractId: hired.contractId, items: proofItems });
    await expect(t.mutation(api.agentExchange.verify, { contractId: hired.contractId })).rejects.toThrow("E_SELF_VERIFICATION_FORBIDDEN");

    const reviewerSubject = "reviewer-independent";
    await t.run(async (ctx) => {
      await ctx.db.insert("workspaceMemberships", {
        workspaceId: seed.workspaceId,
        tokenIdentifier: `https://test-idp.example|${reviewerSubject}`,
        memberLabel: "Independent reviewer",
        role: "reviewer",
        status: "active",
        createdBy: "test",
        createdAt: Date.now(),
      });
    });
    const reviewer = t.withIdentity({ subject: reviewerSubject, issuer: "https://test-idp.example", name: reviewerSubject });
    const verdict = await reviewer.mutation(api.agentExchange.verify, { contractId: hired.contractId });
    expect(verdict).toMatchObject({ marker: "OUTCOME_VERDICT_PASSED", payableCredits: 90 });
    const paid = await t.mutation(api.agentExchange.release, { contractId: hired.contractId });
    expect(paid).toMatchObject({ marker: "OUTCOME_PAYMENT_SETTLED", settledCredits: 90 });
    expect((await t.mutation(api.agentExchange.release, { contractId: hired.contractId })).settledCredits).toBe(0);
    expect((await t.query(api.credits.status, { workspaceId: seed.workspaceId })).account).toMatchObject({ availableCredits: 410, reservedCredits: 0, spentCredits: 90 });
  });

  test("rejects insufficient credits and recursive agent delegation without side effects", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    const accountId = await t.run(async (ctx) => (await ctx.db.query("creditAccounts").withIndex("by_workspace", (q) => q.eq("workspaceId", seed.workspaceId)).unique())?._id);
    if (!accountId) throw new Error("missing credit account");
    await t.run(async (ctx) => ctx.db.patch(accountId, { availableCredits: 50 }));
    await expect(t.mutation(api.agentExchange.hire, hireArgs(String(seed.workspaceId)))).rejects.toThrow("E_OUTCOME_CREDITS_INSUFFICIENT");
    await expect(t.mutation(api.agentExchange.hire, {
      ...hireArgs(String(seed.workspaceId)),
      idempotencyKey: "recursive",
      callerKind: "agent",
      callerAgentId: "agent://buyer",
      mandateDigest: "m".repeat(64),
      delegationDepth: 2,
    })).rejects.toThrow("E_DELEGATION_DEPTH_EXCEEDED");
    expect((await t.query(api.agentExchange.overview, { workspaceId: seed.workspaceId })).contracts).toHaveLength(0);
  });

  test("fails closed on hollow evidence and releases a canceled reservation once", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    const hired = await t.mutation(api.agentExchange.hire, { ...hireArgs(String(seed.workspaceId)), idempotencyKey: "cancel-me" });
    await t.mutation(api.agentExchange.start, { contractId: hired.contractId });
    await expect(t.mutation(api.agentExchange.submitEvidence, { contractId: hired.contractId, items: proofItems.slice(1) })).rejects.toThrow("E_OUTCOME_EVIDENCE_INCOMPLETE");
    const canceled = await t.mutation(api.agentExchange.cancel, { contractId: hired.contractId, disposition: "canceled", reason: "Buyer withdrew the bounded task." });
    expect(canceled).toMatchObject({ marker: "OUTCOME_CONTRACT_TERMINATED", releasedCredits: 90 });
    expect((await t.mutation(api.agentExchange.cancel, { contractId: hired.contractId, disposition: "canceled", reason: "Replay" })).releasedCredits).toBe(0);
    expect((await t.query(api.credits.status, { workspaceId: seed.workspaceId })).account).toMatchObject({ availableCredits: 500, reservedCredits: 0, spentCredits: 0 });
  });
});
