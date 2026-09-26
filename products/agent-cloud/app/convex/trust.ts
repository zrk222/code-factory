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

type CapabilityIssueInput = {
  runId: Id<"runs">;
  subject: string;
  audience: string;
  scope: string;
  resource: string;
  environment: "test" | "production";
  risk: "low" | "moderate" | "high";
  actionDigest: string;
  maxCostCents: number;
  ttlSeconds: number;
};

function validateIssueInput(args: CapabilityIssueInput) {
  const subject = assertText(args.subject, "subject", 120);
  const audience = assertText(args.audience, "audience", 120);
  const scope = assertText(args.scope, "scope", 160);
  const resource = assertText(args.resource, "resource", 300);
  const digest = assertText(args.actionDigest, "action_digest", 120);
  assertIntegerRange(args.maxCostCents, "max_cost", 1, 1000000);
  assertIntegerRange(args.ttlSeconds, "ttl_seconds", 30, 900);
  return { subject, audience, scope, resource, digest };
}

async function loadIssuanceRun(ctx: MutationCtx, runId: Id<"runs">) {
  const run = await ctx.db.get(runId);
  if (!run) throw new Error("E_RUN_NOT_FOUND");
  return run;
}

async function requireActiveAgentSpec(ctx: MutationCtx, agentSpecId: Id<"agentSpecs">) {
  const spec = await ctx.db.get(agentSpecId);
  if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
  if (spec.status !== "active") throw new Error("E_AGENT_NOT_ACTIVE");
  return spec;
}

async function requireApprovedAction(
  ctx: MutationCtx,
  run: { _id: Id<"runs">; actionDigest: string },
  digest: string,
) {
  if (run.actionDigest !== digest) throw new Error("E_CAPABILITY_ACTION_MISMATCH");
  const approval = await ctx.db.query("approvals")
    .withIndex("by_run", (q) => q.eq("runId", run._id))
    .unique();
  if (!approval || approval.status !== "approved" || approval.actionDigest !== digest) {
    throw new Error("E_CAPABILITY_APPROVAL_REQUIRED");
  }
  const approvedBy = approval.decidedBy;
  if (!approvedBy || approvedBy === approval.requestedBy) {
    throw new Error("E_CAPABILITY_SEPARATION_OF_DUTIES");
  }
  return approvedBy;
}

async function assertIssuanceBudget(
  ctx: MutationCtx,
  run: { _id: Id<"runs">; actualCostCents: number },
  spec: { hardBudgetCents: number },
  maxCostCents: number,
) {
  const reservedCostCents = await getReservedCost(ctx, run._id);
  if (run.actualCostCents + reservedCostCents + maxCostCents > spec.hardBudgetCents) {
    throw new Error("E_CAPABILITY_OVER_BUDGET");
  }
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
    const fields = validateIssueInput(args);
    const run = await loadIssuanceRun(ctx, args.runId);
    await requireWorkspaceRole(ctx, run.workspaceId, "operator");
    const spec = await requireActiveAgentSpec(ctx, run.agentSpecId);
    const issuedBy = await requireApprovedAction(ctx, run, fields.digest);
    await assertIssuanceBudget(ctx, run, spec, args.maxCostCents);
    const now = Date.now();
    const grantId = await ctx.db.insert("capabilityGrants", {
      workspaceId: run.workspaceId,
      agentSpecId: run.agentSpecId,
      runId: run._id,
      subject: fields.subject,
      audience: fields.audience,
      scope: fields.scope,
      resource: fields.resource,
      environment: args.environment,
      risk: args.risk,
      policyVersion: "trust-policy.v1",
      actionDigest: fields.digest,
      maxCostCents: args.maxCostCents,
      expiresAt: now + args.ttlSeconds * 1000,
      state: "active",
      issuedBy,
      createdAt: now,
    });
    const fingerprint = await appendTrustEvidence(ctx, grantId, run._id, run.workspaceId, "capability.issued", [fields.audience, fields.scope, fields.resource, fields.digest], now);
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
type ToolCallInput = {
  grantId: Id<"capabilityGrants">;
  requestKey: string;
  subject: string;
  audience: string;
  scope: string;
  resource: string;
  environment: "test" | "production";
  actionDigest: string;
  requestedCostCents: number;
};

function validateToolCallInput(args: ToolCallInput) {
  const requestKey = assertText(args.requestKey, "request_key", 120);
  const subject = assertText(args.subject, "subject", 120);
  const audience = assertText(args.audience, "audience", 120);
  const scope = assertText(args.scope, "scope", 160);
  const resource = assertText(args.resource, "resource", 300);
  const digest = assertText(args.actionDigest, "action_digest", 120);
  assertIntegerRange(args.requestedCostCents, "requested_cost", 1, 1000000);
  return { requestKey, subject, audience, scope, resource, digest };
}

async function loadCapability(ctx: MutationCtx, grantId: Id<"capabilityGrants">) {
  const grant = await ctx.db.get(grantId);
  if (!grant) throw new Error("E_CAPABILITY_NOT_FOUND");
  return grant;
}

function requireUnconsumedCapability(grant: { state: string; expiresAt: number }) {
  if (grant.state === "consumed") throw new Error("E_CAPABILITY_REPLAYED");
  if (grant.state === "revoked") throw new Error("E_CAPABILITY_REVOKED");
  const now = Date.now();
  if (grant.expiresAt <= now) throw new Error("E_CAPABILITY_EXPIRED");
  return now;
}

async function requireActiveRunAndSpec(
  ctx: MutationCtx,
  grant: { runId: Id<"runs">; agentSpecId: Id<"agentSpecs"> },
) {
  const run = await ctx.db.get(grant.runId);
  if (!run) throw new Error("E_RUN_NOT_FOUND");
  const spec = await ctx.db.get(grant.agentSpecId);
  if (!spec || spec.status !== "active") throw new Error("E_AGENT_NOT_ACTIVE");
  return { run, spec };
}

function assertCapabilityMatchesRequest(
  grant: {
    subject: string;
    audience: string;
    scope: string;
    resource: string;
    environment: "test" | "production";
    actionDigest: string;
  },
  run: { actionDigest: string },
  request: {
    subject: string;
    audience: string;
    scope: string;
    resource: string;
    environment: "test" | "production";
    digest: string;
  },
) {
  if (grant.subject !== request.subject) throw new Error("E_CAPABILITY_WRONG_SUBJECT");
  if (grant.audience !== request.audience) throw new Error("E_CAPABILITY_WRONG_AUDIENCE");
  if (grant.scope !== request.scope) throw new Error("E_CAPABILITY_WRONG_SCOPE");
  if (grant.resource !== request.resource) throw new Error("E_CAPABILITY_WRONG_RESOURCE");
  if (grant.environment !== request.environment) throw new Error("E_CAPABILITY_WRONG_ENVIRONMENT");
  if (grant.actionDigest !== request.digest || run.actionDigest !== request.digest) {
    throw new Error("E_CAPABILITY_ACTION_MISMATCH");
  }
}

function assertRequestedCostWithinGrant(requestedCostCents: number, maxCostCents: number) {
  if (requestedCostCents > maxCostCents) throw new Error("E_CAPABILITY_OVER_BUDGET");
}

async function assertAuthorizationBudget(
  ctx: MutationCtx,
  run: { _id: Id<"runs">; actualCostCents: number },
  spec: { hardBudgetCents: number },
  requestedCostCents: number,
) {
  const reservedCostCents = await getReservedCost(ctx, run._id);
  if (run.actualCostCents + reservedCostCents + requestedCostCents > spec.hardBudgetCents) {
    throw new Error("E_CAPABILITY_OVER_BUDGET");
  }
}

async function assertCallKeyUnused(ctx: MutationCtx, runId: Id<"runs">, callKey: string) {
  const existing = await ctx.db.query("costReservations")
    .withIndex("by_run_call", (q) => q.eq("runId", runId).eq("callKey", callKey))
    .unique();
  if (existing) throw new Error("E_CAPABILITY_REPLAYED");
}

async function recordAuthorizedCall(
  ctx: MutationCtx,
  grant: { _id: Id<"capabilityGrants">; workspaceId: Id<"workspaces">; agentSpecId: Id<"agentSpecs">; runId: Id<"runs"> },
  request: ToolCallInput & { digest: string },
  run: { _id: Id<"runs">; workspaceId: Id<"workspaces">; agentSpecId: Id<"agentSpecs"> },
  callKey: string,
  now: number,
) {
  const requestDigest = receiptFingerprint([request.subject, request.audience, request.scope, request.resource, request.environment, request.digest, String(request.requestedCostCents)]);
  const reservationId = await ctx.db.insert("costReservations", {
    workspaceId: run.workspaceId,
    agentSpecId: run.agentSpecId,
    runId: run._id,
    callKey,
    provider: "trust-gateway",
    model: "tool-action",
    estimatedCostCents: request.requestedCostCents,
    state: "reserved",
    createdAt: now,
  });
  await ctx.db.patch(grant._id, { state: "consumed", consumedAt: now });
  await ctx.db.insert("trustDecisions", {
    workspaceId: run.workspaceId,
    agentSpecId: run.agentSpecId,
    runId: run._id,
    capabilityGrantId: grant._id,
    requestKey: request.requestKey,
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
}

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
    const fields = validateToolCallInput(args);
    const grant = await loadCapability(ctx, args.grantId);
    await requireWorkspaceRole(ctx, grant.workspaceId, "operator");
    const now = requireUnconsumedCapability(grant);
    const { run, spec } = await requireActiveRunAndSpec(ctx, grant);
    const request = { ...args, ...fields };
    assertCapabilityMatchesRequest(grant, run, request);
    assertRequestedCostWithinGrant(args.requestedCostCents, grant.maxCostCents);
    await assertAuthorizationBudget(ctx, run, spec, args.requestedCostCents);
    const callKey = `trust:${fields.requestKey}`;
    await assertCallKeyUnused(ctx, run._id, callKey);
    return recordAuthorizedCall(ctx, grant, { ...request, digest: fields.digest }, run, callKey, now);
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
