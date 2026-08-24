import { v } from "convex/values";
import type { Id } from "./_generated/dataModel";
import type { MutationCtx, QueryCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import { assertIntegerRange, assertText, receiptFingerprint } from "./domain";
import { requireWorkspaceRole } from "./access";

type BudgetCtx = MutationCtx | QueryCtx;

export type BudgetSummary = {
  hardLimitCents: number;
  settledCostCents: number;
  reservedCostCents: number;
  remainingCostCents: number;
  utilizationPercent: number;
  terminationReason: "hard-limit-reached" | "budget-available";
};

/** Calculates the six-field public budget status from integer-cent ledger totals. */
export function calculateBudgetSummary(hardLimitCents: number, settledCostCents: number, reservedCostCents: number): BudgetSummary {
  const remainingCostCents = Math.max(0, hardLimitCents - settledCostCents - reservedCostCents);
  return {
    hardLimitCents,
    settledCostCents,
    reservedCostCents,
    remainingCostCents,
    utilizationPercent: Math.min(100, Math.round(((settledCostCents + reservedCostCents) / Math.max(1, hardLimitCents)) * 100)),
    terminationReason: remainingCostCents === 0 ? "hard-limit-reached" : "budget-available",
  };
}

const getBudgetContext = async (ctx: BudgetCtx, runId: Id<"runs">) => {
  const run = await ctx.db.get(runId);
  if (!run) throw new Error("E_RUN_NOT_FOUND");
  const spec = await ctx.db.get(run.agentSpecId);
  if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
  const reservations = await ctx.db
    .query("costReservations")
    .withIndex("by_run_state", (q) => q.eq("runId", run._id).eq("state", "reserved"))
    .collect();
  const reservedCostCents = reservations.reduce((sum, reservation) => sum + reservation.estimatedCostCents, 0);
  return { run, spec, reservations, reservedCostCents };
};

const appendBudgetEvidence = async (
  ctx: MutationCtx,
  runId: Id<"runs">,
  reservationId: Id<"costReservations">,
  workspaceId: Id<"workspaces">,
  event: "budget.reserved" | "budget.reconciled" | "budget.released",
  amountCents: number,
  now: number,
) => {
  const previous = await ctx.db
    .query("receipts")
    .withIndex("by_run_created", (q) => q.eq("runId", runId))
    .order("desc")
    .first();
  const fingerprint = receiptFingerprint([String(runId), String(reservationId), event, String(amountCents), String(now)]);
  await ctx.db.insert("receipts", {
    workspaceId,
    runId,
    costReservationId: reservationId,
    type: "budget-control",
    event,
    fingerprint,
    previousFingerprint: previous?.fingerprint,
    signatureState: "unsigned",
    createdAt: now,
  });
  await ctx.db.insert("auditEvents", {
    workspaceId,
    actor: "budget-gateway@factory.local",
    event,
    targetType: "costReservation",
    targetId: String(reservationId),
    detail: `Budget ledger transition recorded for ${amountCents} integer cents; model content and credentials omitted.`,
    createdAt: now,
  });
  return fingerprint;
};

/** Atomically reserves model-call cost before any future provider invocation. */
export const reserveCall = mutation({
  args: {
    runId: v.id("runs"),
    callKey: v.string(),
    provider: v.string(),
    model: v.string(),
    estimatedCostCents: v.number(),
  },
  handler: async (ctx, args) => {
    const callKey = assertText(args.callKey, "call_key", 120);
    const provider = assertText(args.provider, "provider", 120);
    const model = assertText(args.model, "model", 120);
    assertIntegerRange(args.estimatedCostCents, "estimated_cost", 1, 1000000);
    const { run, spec, reservedCostCents } = await getBudgetContext(ctx, args.runId);
    await requireWorkspaceRole(ctx, run.workspaceId, "operator");
    const existing = await ctx.db
      .query("costReservations")
      .withIndex("by_run_call", (q) => q.eq("runId", run._id).eq("callKey", callKey))
      .unique();
    if (existing) {
      if (existing.provider !== provider || existing.model !== model || existing.estimatedCostCents !== args.estimatedCostCents) {
        throw new Error("E_CALL_KEY_CONFLICT");
      }
      return {
        marker: "BUDGET_RESERVATION_REPLAYED" as const,
        evidenceMarker: "BUDGET_EVIDENCE_REDACTED" as const,
        reservationId: existing._id,
      };
    }
    const committedCostCents = run.actualCostCents + reservedCostCents + args.estimatedCostCents;
    if (committedCostCents > spec.hardBudgetCents) throw new Error("E_BUDGET_EXCEEDED");
    const now = Date.now();
    const reservationId = await ctx.db.insert("costReservations", {
      workspaceId: run.workspaceId,
      agentSpecId: run.agentSpecId,
      runId: run._id,
      callKey,
      provider,
      model,
      estimatedCostCents: args.estimatedCostCents,
      state: "reserved",
      createdAt: now,
    });
    const fingerprint = await appendBudgetEvidence(ctx, run._id, reservationId, run.workspaceId, "budget.reserved", args.estimatedCostCents, now);
    return {
      marker: "BUDGET_RESERVED_ATOMICALLY" as const,
      raceMarker: "BUDGET_RACE_CONTAINED" as const,
      evidenceMarker: "BUDGET_EVIDENCE_REDACTED" as const,
      reservationId,
      fingerprint,
    };
  },
});

/** Reconciles a reservation without permitting actual cost above its ceiling. */
export const reconcileCall = mutation({
  args: { reservationId: v.id("costReservations"), actualCostCents: v.number() },
  handler: async (ctx, args) => {
    assertIntegerRange(args.actualCostCents, "actual_cost", 0, 1000000);
    const reservation = await ctx.db.get(args.reservationId);
    if (!reservation) throw new Error("E_RESERVATION_NOT_FOUND");
    await requireWorkspaceRole(ctx, reservation.workspaceId, "operator");
    if (reservation.state !== "reserved") throw new Error("E_RESERVATION_NOT_ACTIVE");
    if (args.actualCostCents > reservation.estimatedCostCents) throw new Error("E_ACTUAL_EXCEEDS_RESERVATION");
    const run = await ctx.db.get(reservation.runId);
    if (!run) throw new Error("E_RUN_NOT_FOUND");
    const now = Date.now();
    await ctx.db.patch(reservation._id, { state: "settled", actualCostCents: args.actualCostCents, completedAt: now });
    await ctx.db.patch(run._id, { actualCostCents: run.actualCostCents + args.actualCostCents });
    await ctx.db.insert("usageRecords", {
      workspaceId: run.workspaceId,
      runId: run._id,
      estimatedCostCents: reservation.estimatedCostCents,
      actualCostCents: args.actualCostCents,
      createdAt: now,
    });
    const fingerprint = await appendBudgetEvidence(ctx, run._id, reservation._id, run.workspaceId, "budget.reconciled", args.actualCostCents, now);
    return { marker: "BUDGET_RECONCILED" as const, evidenceMarker: "BUDGET_EVIDENCE_REDACTED" as const, fingerprint };
  },
});

/** Releases unused committed cost while preserving append-only evidence. */
export const releaseCall = mutation({
  args: { reservationId: v.id("costReservations") },
  handler: async (ctx, args) => {
    const reservation = await ctx.db.get(args.reservationId);
    if (!reservation) throw new Error("E_RESERVATION_NOT_FOUND");
    await requireWorkspaceRole(ctx, reservation.workspaceId, "operator");
    if (reservation.state !== "reserved") throw new Error("E_RESERVATION_NOT_ACTIVE");
    const now = Date.now();
    await ctx.db.patch(reservation._id, { state: "released", completedAt: now });
    const fingerprint = await appendBudgetEvidence(ctx, reservation.runId, reservation._id, reservation.workspaceId, "budget.released", reservation.estimatedCostCents, now);
    return { marker: "BUDGET_RELEASED" as const, evidenceMarker: "BUDGET_EVIDENCE_REDACTED" as const, fingerprint };
  },
});

/** Explains settled, reserved, and remaining cost from the authoritative ledger. */
export const status = query({
  args: { runId: v.id("runs") },
  handler: async (ctx, args) => {
    const { run, spec, reservedCostCents } = await getBudgetContext(ctx, args.runId);
    await requireWorkspaceRole(ctx, run.workspaceId, "viewer");
    const summary = calculateBudgetSummary(spec.hardBudgetCents, run.actualCostCents, reservedCostCents);
    const reservations = await ctx.db
      .query("costReservations")
      .withIndex("by_run_call", (q) => q.eq("runId", run._id))
      .collect();
    return {
      marker: "BUDGET_STATUS_EXPLAINED" as const,
      summary,
      reservations: reservations.sort((left, right) => right.createdAt - left.createdAt),
    };
  },
});
