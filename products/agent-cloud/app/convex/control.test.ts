import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import schema from "./schema";
import { authenticatedTest } from "./testIdentity.testSupport";

const modules = import.meta.glob("./**/*.ts");

async function seeded() {
  const t = authenticatedTest();
  const result = await t.mutation(api.seed.ensureDemo, {});
  if (!result.agentSpecId) throw new Error("seed did not create an AgentSpec");
  return { t, ...result };
}

describe("PR Assurance control", () => {
  test("seed is idempotent", async () => {
    const { t } = await seeded();
    await t.mutation(api.seed.ensureDemo, {});
    const counts = await t.run(async (ctx) => ({
      workspaces: (await ctx.db.query("workspaces").collect()).length,
      specs: (await ctx.db.query("agentSpecs").collect()).length,
      versions: (await ctx.db.query("agentSpecVersions").collect()).length,
    }));
    expect(counts).toEqual({ workspaces: 1, specs: 1, versions: 1 });
  });

  test("persists AgentSpec and launches exactly six gates", async () => {
    const { t, agentSpecId } = await seeded();
    const saved = await t.mutation(api.control.saveAgentSpec, {
      agentSpecId,
      repository: "acme/ledger",
      providerProfile: "balanced",
      memoryMode: "architecture-history",
      authorityMode: "approval-required",
      hardBudgetCents: 450,
      validators: ["Requirements coverage", "Test suite"],
    });
    expect(saved).toMatchObject({ marker: "AGENT_SPEC_PERSISTED", version: 2 });
    const versions = await t.run(async (ctx) => ctx.db.query("agentSpecVersions").collect());
    expect(versions).toHaveLength(2);
    const launched = await t.mutation(api.control.launchRun, {
      agentSpecId,
      branch: "feature/trust-rail",
      commitSha: "f".repeat(40),
      estimatedCostCents: 127,
    });
    const detail = await t.query(api.control.runDetail, { runId: launched.runId });
    expect(launched.marker).toBe("ASSURANCE_RUN_CREATED");
    expect(detail?.gates).toHaveLength(6);
    expect(detail?.approval?.status).toBe("pending");
    expect(detail?.gates.find((gate) => gate.kind === "model")?.evidenceClass).toBe("heuristic");
  });

  test("rejects an over-budget run before writes", async () => {
    const { t, agentSpecId } = await seeded();
    await t.mutation(api.control.saveAgentSpec, {
      agentSpecId,
      repository: "acme/ledger",
      providerProfile: "economy",
      memoryMode: "run-only",
      authorityMode: "approval-required",
      hardBudgetCents: 100,
      validators: ["Test suite"],
    });
    await expect(
      t.mutation(api.control.launchRun, {
        agentSpecId,
        branch: "feature/too-expensive",
        commitSha: "a".repeat(40),
        estimatedCostCents: 101,
      }),
    ).rejects.toThrow("E_BUDGET_EXCEEDED");
    const count = await t.run(async (ctx) => (await ctx.db.query("runs").collect()).length);
    expect(count).toBe(0);
  });

  test("binds approval to action digest and rejects replay", async () => {
    const { t, agentSpecId } = await seeded();
    const launched = await t.mutation(api.control.launchRun, {
      agentSpecId,
      branch: "feature/receipts",
      commitSha: "b".repeat(40),
      estimatedCostCents: 90,
    });
    const detail = await t.query(api.control.runDetail, { runId: launched.runId });
    if (!detail?.approval) throw new Error("approval missing");
    await expect(
      t.mutation(api.control.decideApproval, {
        approvalId: detail.approval._id,
        actionDigest: "wrong-digest",
        decision: "approved",
        rationale: "Looks safe.",
      }),
    ).rejects.toThrow("E_ACTION_DIGEST_MISMATCH");
    const decided = await t.mutation(api.control.decideApproval, {
      approvalId: detail.approval._id,
      actionDigest: detail.approval.actionDigest,
      decision: "approved",
      rationale: "All deterministic gates passed.",
    });
    expect(decided.marker).toBe("APPROVAL_DECISION_BOUND");
    await expect(
      t.mutation(api.control.decideApproval, {
        approvalId: detail.approval._id,
        actionDigest: detail.approval.actionDigest,
        decision: "approved",
        rationale: "Replay.",
      }),
    ).rejects.toThrow("E_APPROVAL_ALREADY_DECIDED");
  });
});
