import { v } from "convex/values";
import type { Id } from "./_generated/dataModel";
import type { MutationCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";
import { assertIntegerRange, assertText, receiptFingerprint } from "./domain";
import { quoteBlueprintCredits } from "./pricing";

const MONTH_MS = 30 * 24 * 60 * 60 * 1000;
export const planCatalog = [
  { plan: "starter" as const, name: "Starter", monthlyCredits: 500, agentLimit: 2, audience: "Solo builders testing standard recipes" },
  { plan: "growth" as const, name: "Growth", monthlyCredits: 2500, agentLimit: 10, audience: "Operators running recurring customer workflows" },
  { plan: "business" as const, name: "Business", monthlyCredits: 10000, agentLimit: 50, audience: "Teams using premium memory, connectors, and approvals" },
  { plan: "enterprise" as const, name: "Enterprise", monthlyCredits: 50000, agentLimit: 500, audience: "Organizations needing pooled credits, SSO, SCIM, residency, and SLAs" },
];

export async function ensureCreditAccount(ctx: MutationCtx, workspaceId: Id<"workspaces">) {
  const existing = await ctx.db.query("creditAccounts").withIndex("by_workspace", (q) => q.eq("workspaceId", workspaceId)).unique();
  if (existing) return existing._id;
  const now = Date.now();
  const accountId = await ctx.db.insert("creditAccounts", { workspaceId, plan: "starter", availableCredits: 500, reservedCredits: 0, spentCredits: 0, monthlyAllocation: 500, periodStart: now, periodEnd: now + MONTH_MS, status: "active", updatedAt: now });
  await ctx.db.insert("creditTransactions", { workspaceId, kind: "allocation", credits: 500, availableAfter: 500, reservedAfter: 0, reference: "starter-period-allocation", createdAt: now });
  return accountId;
}

/** Quotes server-owned fixed template or custom ingredient pricing. */
export const quote = query({
  args: { blueprintId: v.id("agentBlueprints") },
  handler: async (ctx, args) => {
    const blueprint = await ctx.db.get(args.blueprintId);
    if (!blueprint) throw new Error("E_BLUEPRINT_NOT_FOUND");
    await requireWorkspaceRole(ctx, blueprint.workspaceId, "viewer");
    return { marker: "BLUEPRINT_CREDIT_QUOTED" as const, ...quoteBlueprintCredits(blueprint) };
  },
});

/** Atomically reserves the exact server-owned blueprint price once. */
export const reserveBlueprint = mutation({
  args: { blueprintId: v.id("agentBlueprints"), idempotencyKey: v.string() },
  handler: async (ctx, args) => {
    const blueprint = await ctx.db.get(args.blueprintId);
    if (!blueprint) throw new Error("E_BLUEPRINT_NOT_FOUND");
    await requireWorkspaceRole(ctx, blueprint.workspaceId, "admin");
    const idempotencyKey = assertText(args.idempotencyKey, "idempotency_key", 120);
    const existing = await ctx.db.query("creditReservations").withIndex("by_workspace_key", (q) => q.eq("workspaceId", blueprint.workspaceId).eq("idempotencyKey", idempotencyKey)).unique();
    if (existing) return { marker: "CREDIT_RESERVATION_REPLAYED" as const, reservationId: existing._id, quotedCredits: existing.quotedCredits };
    const account = await ctx.db.query("creditAccounts").withIndex("by_workspace", (q) => q.eq("workspaceId", blueprint.workspaceId)).unique();
    if (!account || account.status !== "active") throw new Error("E_CREDIT_ACCOUNT_INACTIVE");
    const quotedCredits = quoteBlueprintCredits(blueprint).total;
    if (account.availableCredits < quotedCredits) throw new Error("E_INSUFFICIENT_CREDITS");
    const now = Date.now();
    const availableCredits = account.availableCredits - quotedCredits;
    const reservedCredits = account.reservedCredits + quotedCredits;
    const reservationId = await ctx.db.insert("creditReservations", { workspaceId: blueprint.workspaceId, agentSpecId: blueprint.agentSpecId, blueprintId: blueprint._id, idempotencyKey, quotedCredits, state: "reserved", createdAt: now });
    await ctx.db.patch(account._id, { availableCredits, reservedCredits, updatedAt: now });
    await ctx.db.insert("creditTransactions", { workspaceId: blueprint.workspaceId, reservationId, kind: "reserve", credits: quotedCredits, availableAfter: availableCredits, reservedAfter: reservedCredits, reference: idempotencyKey, createdAt: now });
    return { marker: "BLUEPRINT_CREDITS_RESERVED" as const, reservationId, quotedCredits, availableCredits };
  },
});

/** Settles actual platform credits and releases every unused reserved credit. */
export const settle = mutation({
  args: { reservationId: v.id("creditReservations"), actualCredits: v.number() },
  handler: async (ctx, args) => {
    const reservation = await ctx.db.get(args.reservationId);
    if (!reservation) throw new Error("E_CREDIT_RESERVATION_NOT_FOUND");
    await requireWorkspaceRole(ctx, reservation.workspaceId, "admin");
    if (reservation.state !== "reserved") throw new Error("E_CREDIT_RESERVATION_NOT_ACTIVE");
    assertIntegerRange(args.actualCredits, "actual_credits", 0, reservation.quotedCredits);
    const account = await ctx.db.query("creditAccounts").withIndex("by_workspace", (q) => q.eq("workspaceId", reservation.workspaceId)).unique();
    if (!account) throw new Error("E_CREDIT_ACCOUNT_NOT_FOUND");
    const now = Date.now();
    const released = reservation.quotedCredits - args.actualCredits;
    const availableCredits = account.availableCredits + released;
    const reservedCredits = account.reservedCredits - reservation.quotedCredits;
    const spentCredits = account.spentCredits + args.actualCredits;
    await ctx.db.patch(reservation._id, { actualCredits: args.actualCredits, state: "settled", completedAt: now });
    await ctx.db.patch(account._id, { availableCredits, reservedCredits, spentCredits, updatedAt: now });
    await ctx.db.insert("creditTransactions", { workspaceId: reservation.workspaceId, reservationId: reservation._id, kind: "settle", credits: args.actualCredits, availableAfter: availableCredits, reservedAfter: reservedCredits, reference: reservation.idempotencyKey, createdAt: now });
    const previous = await ctx.db.query("receipts").withIndex("by_workspace_created", (q) => q.eq("workspaceId", reservation.workspaceId)).order("desc").first();
    const fingerprint = receiptFingerprint([String(reservation._id), String(args.actualCredits), String(released), String(now)]);
    await ctx.db.insert("receipts", { workspaceId: reservation.workspaceId, agentSpecId: reservation.agentSpecId, type: "platform-credit", event: "credits.settled", fingerprint, previousFingerprint: previous?.fingerprint, signatureState: "unsigned", createdAt: now });
    return { marker: "BLUEPRINT_CREDITS_SETTLED" as const, actualCredits: args.actualCredits, releasedCredits: released, availableCredits, fingerprint };
  },
});

/** Explains the credit balance and recent immutable ledger entries. */
export const status = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    await requireWorkspaceRole(ctx, args.workspaceId, "viewer");
    const account = await ctx.db.query("creditAccounts").withIndex("by_workspace", (q) => q.eq("workspaceId", args.workspaceId)).unique();
    const transactions = await ctx.db.query("creditTransactions").withIndex("by_workspace_created", (q) => q.eq("workspaceId", args.workspaceId)).order("desc").take(50);
    return { marker: "PLATFORM_CREDITS_EXPLAINED" as const, account, transactions, inferenceLedgerMarker: "BYOK_INFERENCE_SEPARATE" as const };
  },
});

/** Publishes transparent tier allocations without enabling an unverified billing change. */
export const plans = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    await requireWorkspaceRole(ctx, args.workspaceId, "viewer");
    return { marker: "CREDIT_PLAN_CATALOG" as const, plans: planCatalog };
  },
});
