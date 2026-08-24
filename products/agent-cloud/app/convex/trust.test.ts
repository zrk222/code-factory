import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import schema from "./schema";
import { authenticatedTest } from "./testIdentity.testSupport";

const modules = import.meta.glob("./**/*.ts");

async function approvedRun() {
  const t = authenticatedTest();
  const seed = await t.mutation(api.seed.ensureDemo, {});
  if (!seed.agentSpecId) throw new Error("seed did not create an AgentSpec");
  const launched = await t.mutation(api.control.launchRun, {
    agentSpecId: seed.agentSpecId,
    branch: "feature/trust-gateway",
    commitSha: "d".repeat(40),
    estimatedCostCents: 127,
  });
  const run = await t.run(async (ctx) => ctx.db.get(launched.runId));
  if (!run) throw new Error("run missing");
  await t.mutation(api.control.decideApproval, {
    approvalId: launched.approvalId,
    actionDigest: run.actionDigest,
    decision: "approved",
    rationale: "Independent reviewer verified the exact branch-write action.",
  });
  return { t, run };
}

const grantArgs = (run: { _id: Id<"runs">; actionDigest: string; branch: string }) => ({
  runId: run._id,
  subject: "pr-assurance-agent",
  audience: "github-connector",
  scope: "repository:branch-write",
  resource: `branch:${run.branch}`,
  environment: "test" as const,
  risk: "high" as const,
  actionDigest: run.actionDigest,
  maxCostCents: 100,
  ttlSeconds: 300,
});

const requestArgs = (grantId: Id<"capabilityGrants">, run: { actionDigest: string; branch: string }) => ({
  grantId,
  requestKey: "branch-write-01",
  subject: "pr-assurance-agent",
  audience: "github-connector",
  scope: "repository:branch-write",
  resource: `branch:${run.branch}`,
  environment: "test" as const,
  actionDigest: run.actionDigest,
  requestedCostCents: 75,
});

async function counts(t: ReturnType<typeof convexTest>) {
  return t.run(async (ctx) => ({
    grants: (await ctx.db.query("capabilityGrants").collect()).length,
    decisions: (await ctx.db.query("trustDecisions").collect()).length,
    reservations: (await ctx.db.query("costReservations").collect()).length,
    receipts: (await ctx.db.query("receipts").collect()).length,
    audits: (await ctx.db.query("auditEvents").collect()).length,
  }));
}

describe("execution-time trust capabilities", () => {
  test("issues an approval-bound short-lived capability and authorizes exactly once", async () => {
    const { t, run } = await approvedRun();
    const issued = await t.mutation(api.trust.issueCapability, grantArgs(run));
    expect(issued).toMatchObject({
      marker: "CAPABILITY_ISSUED",
      lifetimeMarker: "CAPABILITY_SHORT_LIVED",
      approvalMarker: "CAPABILITY_APPROVAL_BOUND",
    });
    const authorized = await t.mutation(api.trust.authorizeToolCall, requestArgs(issued.grantId, run));
    expect(authorized).toMatchObject({
      marker: "TOOL_CALL_AUTHORIZED",
      scopeMarker: "CAPABILITY_SCOPE_ENFORCED",
      replayMarker: "CAPABILITY_REPLAY_BLOCKED",
      budgetMarker: "CAPABILITY_BUDGET_BOUND",
    });
    await expect(t.mutation(api.trust.authorizeToolCall, requestArgs(issued.grantId, run))).rejects.toThrow("E_CAPABILITY_REPLAYED");
    const status = await t.query(api.trust.status, { runId: run._id });
    expect(status).toMatchObject({ marker: "TRUST_DECISION_EXPLAINED", policyVersion: "trust-policy.v1" });
    expect(status.grants[0].state).toBe("consumed");
    expect(status.decisions[0]).toMatchObject({ decision: "allow", reasonCode: "CAPABILITY_AUTHORIZED" });
  });

  test("rejects wrong audience and wrong resource before every side effect", async () => {
    const { t, run } = await approvedRun();
    const issued = await t.mutation(api.trust.issueCapability, grantArgs(run));
    const before = await counts(t);
    await expect(t.mutation(api.trust.authorizeToolCall, { ...requestArgs(issued.grantId, run), audience: "slack-connector" }))
      .rejects.toThrow("E_CAPABILITY_WRONG_AUDIENCE");
    await expect(t.mutation(api.trust.authorizeToolCall, { ...requestArgs(issued.grantId, run), resource: "branch:main" }))
      .rejects.toThrow("E_CAPABILITY_WRONG_RESOURCE");
    expect(await counts(t)).toEqual(before);
  });

  test("rejects expired capability before every side effect", async () => {
    const { t, run } = await approvedRun();
    const issued = await t.mutation(api.trust.issueCapability, grantArgs(run));
    await t.run(async (ctx) => ctx.db.patch(issued.grantId, { expiresAt: Date.now() - 1 }));
    const before = await counts(t);
    await expect(t.mutation(api.trust.authorizeToolCall, requestArgs(issued.grantId, run))).rejects.toThrow("E_CAPABILITY_EXPIRED");
    expect(await counts(t)).toEqual(before);
  });

  test("revocation blocks authorization and preserves redacted evidence", async () => {
    const { t, run } = await approvedRun();
    const issued = await t.mutation(api.trust.issueCapability, grantArgs(run));
    const revoked = await t.mutation(api.trust.revokeCapability, { grantId: issued.grantId, reason: "Operator stopped the connector action." });
    expect(revoked).toMatchObject({ marker: "CAPABILITY_REVOKED", enforcementMarker: "CAPABILITY_REVOCATION_ENFORCED" });
    await expect(t.mutation(api.trust.authorizeToolCall, requestArgs(issued.grantId, run))).rejects.toThrow("E_CAPABILITY_REVOKED");
    const evidence = await t.run(async (ctx) => ({
      receipts: await ctx.db.query("receipts").collect(),
      audits: await ctx.db.query("auditEvents").collect(),
    }));
    expect(evidence.receipts.filter((receipt) => receipt.type === "trust-decision")).toHaveLength(2);
    expect(JSON.stringify(evidence)).not.toMatch(/api[_-]?key|secret|token|credential=/i);
  });

  test("rejects capability issuance and authorization that exceed the authoritative budget", async () => {
    const { t, run } = await approvedRun();
    const beforeIssue = await counts(t);
    await expect(t.mutation(api.trust.issueCapability, { ...grantArgs(run), maxCostCents: 331 })).rejects.toThrow("E_CAPABILITY_OVER_BUDGET");
    expect(await counts(t)).toEqual(beforeIssue);
    const issued = await t.mutation(api.trust.issueCapability, grantArgs(run));
    const beforeAuthorize = await counts(t);
    await expect(t.mutation(api.trust.authorizeToolCall, { ...requestArgs(issued.grantId, run), requestedCostCents: 101 }))
      .rejects.toThrow("E_CAPABILITY_OVER_BUDGET");
    expect(await counts(t)).toEqual(beforeAuthorize);
  });
});
