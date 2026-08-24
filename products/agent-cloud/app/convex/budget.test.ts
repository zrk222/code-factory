import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { calculateBudgetSummary } from "./budget";
import schema from "./schema";
import { authenticatedTest } from "./testIdentity.testSupport";

const modules = import.meta.glob("./**/*.ts");

async function runWithBudget() {
  const t = authenticatedTest();
  const seed = await t.mutation(api.seed.ensureDemo, {});
  if (!seed.agentSpecId) throw new Error("seed did not create an AgentSpec");
  const launched = await t.mutation(api.control.launchRun, {
    agentSpecId: seed.agentSpecId,
    branch: "feature/atomic-budget",
    commitSha: "c".repeat(40),
    estimatedCostCents: 127,
  });
  return { t, runId: launched.runId };
}

async function reserve(
  t: ReturnType<typeof convexTest>,
  runId: Id<"runs">,
  callKey: string,
  estimatedCostCents: number,
) {
  return t.mutation(api.budget.reserveCall, {
    runId,
    callKey,
    provider: "openai",
    model: "gpt-5-mini",
    estimatedCostCents,
  });
}

describe("atomic model-call budget enforcement", () => {
  test("calculates the exact six-field budget explanation", () => {
    expect(calculateBudgetSummary(450, 120, 200)).toEqual({
      hardLimitCents: 450,
      settledCostCents: 120,
      reservedCostCents: 200,
      remainingCostCents: 130,
      utilizationPercent: 71,
      terminationReason: "budget-available",
    });
  });

  test("contains concurrent reservation contention below the hard ceiling", async () => {
    const { t, runId } = await runWithBudget();
    const results = await Promise.allSettled([
      reserve(t, runId, "parallel-a", 200),
      reserve(t, runId, "parallel-b", 200),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(results.find((result) => result.status === "fulfilled")?.value).toMatchObject({
      marker: "BUDGET_RESERVED_ATOMICALLY",
      raceMarker: "BUDGET_RACE_CONTAINED",
    });
    expect(String(results.find((result) => result.status === "rejected")?.reason)).toContain("E_BUDGET_EXCEEDED");
    const status = await t.query(api.budget.status, { runId });
    expect(status.summary).toEqual({
      hardLimitCents: 450,
      settledCostCents: 120,
      reservedCostCents: 200,
      remainingCostCents: 130,
      utilizationPercent: 71,
      terminationReason: "budget-available",
    });
  });

  test("rejects over-budget admission before every side effect", async () => {
    const { t, runId } = await runWithBudget();
    const before = await t.run(async (ctx) => ({
      reservations: (await ctx.db.query("costReservations").collect()).length,
      usage: (await ctx.db.query("usageRecords").collect()).length,
      receipts: (await ctx.db.query("receipts").collect()).length,
      audits: (await ctx.db.query("auditEvents").collect()).length,
    }));
    await expect(reserve(t, runId, "too-expensive", 331)).rejects.toThrow("E_BUDGET_EXCEEDED");
    const after = await t.run(async (ctx) => ({
      reservations: (await ctx.db.query("costReservations").collect()).length,
      usage: (await ctx.db.query("usageRecords").collect()).length,
      receipts: (await ctx.db.query("receipts").collect()).length,
      audits: (await ctx.db.query("auditEvents").collect()).length,
    }));
    expect(after).toEqual(before);
  });

  test("replays identical call keys without writes and rejects conflicting reuse", async () => {
    const { t, runId } = await runWithBudget();
    const first = await reserve(t, runId, "stable-call", 50);
    const before = await t.run(async (ctx) => ({
      reservations: (await ctx.db.query("costReservations").collect()).length,
      receipts: (await ctx.db.query("receipts").collect()).length,
      audits: (await ctx.db.query("auditEvents").collect()).length,
    }));
    const replay = await reserve(t, runId, "stable-call", 50);
    expect(replay).toMatchObject({ marker: "BUDGET_RESERVATION_REPLAYED", reservationId: first.reservationId });
    const after = await t.run(async (ctx) => ({
      reservations: (await ctx.db.query("costReservations").collect()).length,
      receipts: (await ctx.db.query("receipts").collect()).length,
      audits: (await ctx.db.query("auditEvents").collect()).length,
    }));
    expect(after).toEqual(before);
    await expect(t.mutation(api.budget.reserveCall, {
      runId,
      callKey: "stable-call",
      provider: "anthropic",
      model: "claude-haiku",
      estimatedCostCents: 50,
    })).rejects.toThrow("E_CALL_KEY_CONFLICT");
  });

  test("reconciles within reservation, refuses excess actual cost, and releases unused commitment", async () => {
    const { t, runId } = await runWithBudget();
    const settled = await reserve(t, runId, "settle-me", 100);
    const released = await reserve(t, runId, "release-me", 50);
    await expect(t.mutation(api.budget.reconcileCall, { reservationId: settled.reservationId, actualCostCents: 101 }))
      .rejects.toThrow("E_ACTUAL_EXCEEDS_RESERVATION");
    const before = await t.run(async (ctx) => ctx.db.get(settled.reservationId));
    expect(before?.state).toBe("reserved");
    const reconciled = await t.mutation(api.budget.reconcileCall, { reservationId: settled.reservationId, actualCostCents: 80 });
    expect(reconciled).toMatchObject({ marker: "BUDGET_RECONCILED", evidenceMarker: "BUDGET_EVIDENCE_REDACTED" });
    const releaseResult = await t.mutation(api.budget.releaseCall, { reservationId: released.reservationId });
    expect(releaseResult.marker).toBe("BUDGET_RELEASED");
    const status = await t.query(api.budget.status, { runId });
    expect(status.summary).toMatchObject({ settledCostCents: 200, reservedCostCents: 0, remainingCostCents: 250 });
    expect(status.reservations.map((reservation) => reservation.state).sort()).toEqual(["released", "settled"]);
    const evidence = await t.run(async (ctx) => ({
      usage: await ctx.db.query("usageRecords").collect(),
      receipts: await ctx.db.query("receipts").collect(),
      audits: await ctx.db.query("auditEvents").collect(),
    }));
    expect(evidence.usage).toHaveLength(2);
    expect(evidence.receipts.filter((receipt) => receipt.type === "budget-control")).toHaveLength(4);
    expect(JSON.stringify({ receipts: evidence.receipts, audits: evidence.audits })).not.toMatch(/prompt|response|api[_-]?key|secret/i);
  });
});
