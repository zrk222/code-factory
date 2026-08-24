import { v } from "convex/values";
import type { Id } from "./_generated/dataModel";
import type { MutationCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import { assertIntegerRange, assertText, receiptFingerprint } from "./domain";
import { requireWorkspaceRole } from "./access";

const environment = v.union(v.literal("test"), v.literal("production"));
const risk = v.union(v.literal("low"), v.literal("moderate"), v.literal("high"));

type EvidenceEvent = "capability.issued" | "capability.authorized" | "capability.revoked";

async function appendTrustEvidence(
  ctx: MutationCtx,
  grantId: Id<"capabilityGrants">,
  runId: Id<"runs">,
  workspaceId: Id<"workspaces">,
  event: EvidenceEvent,
  semanticParts: string[],
  now: number,
) {
  const previous = await ctx.db
    .query("receipts")
    .withIndex("by_run_created", (q) => q.eq("runId", runId))
    .order("desc")
    .first();
  const fingerprint = receiptFingerprint([String(runId), String(grantId), event, ...semanticParts, String(now)]);
  await ctx.db.insert("receipts", {
    workspaceId,
    runId,
    capabilityGrantId: grantId,
    type: "trust-decision",
    event,
    fingerprint,
    previousFingerprint: previous?.fingerprint,
    signatureState: "unsigned",
    createdAt: now,
  });
  await ctx.db.insert("auditEvents", {
    workspaceId,
    actor: "trust-gateway@factory.local",
    event,
    targetType: "capabilityGrant",
    targetId: String(grantId),
    detail: `Trust policy transition recorded under trust-policy.v1; credentials and tool payload omitted.`,
    createdAt: now,
  });
  return fingerprint;
}

async function getReservedCost(ctx: MutationCtx, runId: Id<"runs">) {
  const reservations = await ctx.db
    .query("costReservations")
    .withIndex("by_run_state", (q) => q.eq("runId", runId).eq("state", "reserved"))
    .collect();
  return reservations.reduce((sum, reservation) => sum + reservation.estimatedCostCents, 0);
}

/** Issues a short-lived local capability record bound to one approved run action. */
export const issueCapability = mutation({
  args: {
    runId: v.id("runs"),
    subject: v.string(),
    audience: v.string(),
    scope: v.string(),
    resource: v.string(),
    environment,
    risk,
    actionDigest: v.string(),
    maxCostCents: v.number(),
    ttlSeconds: v.number(),
  },
  handler: async (ctx, args) => {
    const subject = assertText(args.subject, "subject", 120);
    const audience = assertText(args.audience, "audience", 120);
    const scope = assertText(args.scope, "scope", 160);
    const resource = assertText(args.resource, "resource", 300);
    const digest = assertText(args.actionDigest, "action_digest", 120);
    assertIntegerRange(args.maxCostCents, "max_cost", 1, 1000000);
    assertIntegerRange(args.ttlSeconds, "ttl_seconds", 30, 900);
    const run = await ctx.db.get(args.runId);
    if (!run) throw new Error("E_RUN_NOT_FOUND");
    await requireWorkspaceRole(ctx, run.workspaceId, "operator");
    const spec = await ctx.db.get(run.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    if (spec.status !== "active") throw new Error("E_AGENT_NOT_ACTIVE");
    if (run.actionDigest !== digest) throw new Error("E_CAPABILITY_ACTION_MISMATCH");
    const approval = await ctx.db.query("approvals").withIndex("by_run", (q) => q.eq("runId", run._id)).unique();
    if (!approval || approval.status !== "approved" || approval.actionDigest !== digest) throw new Error("E_CAPABILITY_APPROVAL_REQUIRED");
    if (!approval.decidedBy || approval.decidedBy === approval.requestedBy) throw new Error("E_CAPABILITY_SEPARATION_OF_DUTIES");
    const reservedCostCents = await getReservedCost(ctx, run._id);
    if (run.actualCostCents + reservedCostCents + args.maxCostCents > spec.hardBudgetCents) {
      throw new Error("E_CAPABILITY_OVER_BUDGET");
    }
    const now = Date.now();
    const grantId = await ctx.db.insert("capabilityGrants", {
      workspaceId: run.workspaceId,
      agentSpecId: run.agentSpecId,
      runId: run._id,
      subject,
      audience,
      scope,
      resource,
      environment: args.environment,
      risk: args.risk,
      policyVersion: "trust-policy.v1",
      actionDigest: digest,
      maxCostCents: args.maxCostCents,
      expiresAt: now + args.ttlSeconds * 1000,
      state: "active",
      issuedBy: approval.decidedBy,
      createdAt: now,
    });
    const fingerprint = await appendTrustEvidence(ctx, grantId, run._id, run.workspaceId, "capability.issued", [audience, scope, resource, digest], now);
    return {
      marker: "CAPABILITY_ISSUED" as const,
      lifetimeMarker: "CAPABILITY_SHORT_LIVED" as const,
      approvalMarker: "CAPABILITY_APPROVAL_BOUND" as const,
      evidenceMarker: "TRUST_EVIDENCE_REDACTED" as const,
      grantId,
      expiresAt: now + args.ttlSeconds * 1000,
      fingerprint,
    };
  },
});

/** Authorizes one exact tool call and atomically reserves its maximum cost. */
export const authorizeToolCall = mutation({
  args: {
    grantId: v.id("capabilityGrants"),
    requestKey: v.string(),
    subject: v.string(),
    audience: v.string(),
    scope: v.string(),
    resource: v.string(),
    environment,
    actionDigest: v.string(),
    requestedCostCents: v.number(),
  },
  handler: async (ctx, args) => {
    const requestKey = assertText(args.requestKey, "request_key", 120);
    const subject = assertText(args.subject, "subject", 120);
    const audience = assertText(args.audience, "audience", 120);
    const scope = assertText(args.scope, "scope", 160);
    const resource = assertText(args.resource, "resource", 300);
    const digest = assertText(args.actionDigest, "action_digest", 120);
    assertIntegerRange(args.requestedCostCents, "requested_cost", 1, 1000000);
    const grant = await ctx.db.get(args.grantId);
    if (!grant) throw new Error("E_CAPABILITY_NOT_FOUND");
    await requireWorkspaceRole(ctx, grant.workspaceId, "operator");
    if (grant.state === "consumed") throw new Error("E_CAPABILITY_REPLAYED");
    if (grant.state === "revoked") throw new Error("E_CAPABILITY_REVOKED");
    const now = Date.now();
    if (grant.expiresAt <= now) throw new Error("E_CAPABILITY_EXPIRED");
    const run = await ctx.db.get(grant.runId);
    if (!run) throw new Error("E_RUN_NOT_FOUND");
    const spec = await ctx.db.get(grant.agentSpecId);
    if (!spec || spec.status !== "active") throw new Error("E_AGENT_NOT_ACTIVE");
    if (grant.subject !== subject) throw new Error("E_CAPABILITY_WRONG_SUBJECT");
    if (grant.audience !== audience) throw new Error("E_CAPABILITY_WRONG_AUDIENCE");
    if (grant.scope !== scope) throw new Error("E_CAPABILITY_WRONG_SCOPE");
    if (grant.resource !== resource) throw new Error("E_CAPABILITY_WRONG_RESOURCE");
    if (grant.environment !== args.environment) throw new Error("E_CAPABILITY_WRONG_ENVIRONMENT");
    if (grant.actionDigest !== digest || run.actionDigest !== digest) throw new Error("E_CAPABILITY_ACTION_MISMATCH");
    if (args.requestedCostCents > grant.maxCostCents) throw new Error("E_CAPABILITY_OVER_BUDGET");
    const reservedCostCents = await getReservedCost(ctx, run._id);
    if (run.actualCostCents + reservedCostCents + args.requestedCostCents > spec.hardBudgetCents) throw new Error("E_CAPABILITY_OVER_BUDGET");
    const callKey = `trust:${requestKey}`;
    const existing = await ctx.db.query("costReservations").withIndex("by_run_call", (q) => q.eq("runId", run._id).eq("callKey", callKey)).unique();
    if (existing) throw new Error("E_CAPABILITY_REPLAYED");
    const requestDigest = receiptFingerprint([subject, audience, scope, resource, args.environment, digest, String(args.requestedCostCents)]);
    const reservationId = await ctx.db.insert("costReservations", {
      workspaceId: run.workspaceId,
      agentSpecId: run.agentSpecId,
      runId: run._id,
      callKey,
      provider: "trust-gateway",
      model: "tool-action",
      estimatedCostCents: args.requestedCostCents,
      state: "reserved",
      createdAt: now,
    });
    await ctx.db.patch(grant._id, { state: "consumed", consumedAt: now });
    await ctx.db.insert("trustDecisions", {
      workspaceId: run.workspaceId,
      agentSpecId: run.agentSpecId,
      runId: run._id,
      capabilityGrantId: grant._id,
      requestKey,
      decision: "allow",
      reasonCode: "CAPABILITY_AUTHORIZED",
      requestDigest,
      policyVersion: "trust-policy.v1",
      costReservationId: reservationId,
      createdAt: now,
    });
    const fingerprint = await appendTrustEvidence(ctx, grant._id, run._id, run.workspaceId, "capability.authorized", [requestDigest, String(reservationId)], now);
    return {
      marker: "TOOL_CALL_AUTHORIZED" as const,
      scopeMarker: "CAPABILITY_SCOPE_ENFORCED" as const,
      replayMarker: "CAPABILITY_REPLAY_BLOCKED" as const,
      budgetMarker: "CAPABILITY_BUDGET_BOUND" as const,
      evidenceMarker: "TRUST_EVIDENCE_REDACTED" as const,
      reservationId,
      requestDigest,
      fingerprint,
    };
  },
});

/** Revokes an active capability before it can authorize a tool call. */
export const revokeCapability = mutation({
  args: { grantId: v.id("capabilityGrants"), reason: v.string() },
  handler: async (ctx, args) => {
    const reason = assertText(args.reason, "revocation_reason", 500);
    const grant = await ctx.db.get(args.grantId);
    if (!grant) throw new Error("E_CAPABILITY_NOT_FOUND");
    await requireWorkspaceRole(ctx, grant.workspaceId, "operator");
    if (grant.state !== "active") throw new Error("E_CAPABILITY_NOT_ACTIVE");
    const now = Date.now();
    await ctx.db.patch(grant._id, { state: "revoked", revokedAt: now, revocationReason: reason });
    const fingerprint = await appendTrustEvidence(ctx, grant._id, grant.runId, grant.workspaceId, "capability.revoked", [reason], now);
    return { marker: "CAPABILITY_REVOKED" as const, enforcementMarker: "CAPABILITY_REVOCATION_ENFORCED" as const, fingerprint };
  },
});

/** Returns explainable capability and allow-decision history for one run. */
export const status = query({
  args: { runId: v.id("runs") },
  handler: async (ctx, args) => {
    const run = await ctx.db.get(args.runId);
    if (!run) throw new Error("E_RUN_NOT_FOUND");
    await requireWorkspaceRole(ctx, run.workspaceId, "viewer");
    const [grants, decisions] = await Promise.all([
      ctx.db.query("capabilityGrants").withIndex("by_run_state", (q) => q.eq("runId", args.runId)).collect(),
      ctx.db.query("trustDecisions").withIndex("by_run_created", (q) => q.eq("runId", args.runId)).collect(),
    ]);
    return {
      marker: "TRUST_DECISION_EXPLAINED" as const,
      policyVersion: "trust-policy.v1" as const,
      grants: grants.sort((left, right) => right.createdAt - left.createdAt),
      decisions: decisions.sort((left, right) => right.createdAt - left.createdAt),
    };
  },
});
