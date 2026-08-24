import { v } from "convex/values";
import type { MutationCtx } from "./_generated/server";
import { mutation } from "./_generated/server";
import { assertIntegerRange, assertText, receiptFingerprint } from "./domain";
import { requireWorkspaceRole } from "./access";

async function appendEvidence(ctx: MutationCtx, workspaceId: any, agentSpecId: any, event: string, detail: string, now: number) {
  const previous = await ctx.db.query("receipts").withIndex("by_workspace_created", (q) => q.eq("workspaceId", workspaceId)).order("desc").first();
  const fingerprint = receiptFingerprint([String(agentSpecId), event, detail, String(now)]);
  await ctx.db.insert("receipts", { workspaceId, agentSpecId, type: "release-safety", event, fingerprint, previousFingerprint: previous?.fingerprint, signatureState: "unsigned", createdAt: now });
  await ctx.db.insert("auditEvents", { workspaceId, actor: "operator@factory.local", event, targetType: "agentSpec", targetId: String(agentSpecId), detail, createdAt: now });
  return fingerprint;
}

export const startCanary = mutation({
  args: { agentSpecId: v.id("agentSpecs"), targetVersion: v.number(), deterministicGatesPassed: v.number(), modelScore: v.number(), trafficPercent: v.number(), reason: v.string() },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "operator");
    const version = await ctx.db.query("agentSpecVersions").withIndex("by_agent_version", (q) => q.eq("agentSpecId", spec._id).eq("version", args.targetVersion)).unique();
    if (!version) throw new Error("E_VERSION_NOT_FOUND");
    if (args.deterministicGatesPassed !== 6 || !Number.isInteger(args.modelScore) || args.modelScore < 80 || args.modelScore > 100) throw new Error("E_REEVALUATION_REQUIRED");
    assertIntegerRange(args.trafficPercent, "traffic_percent", 5, 25);
    const active = await ctx.db.query("releaseCandidates").withIndex("by_agent_status", (q) => q.eq("agentSpecId", spec._id).eq("status", "active")).unique();
    if (active) throw new Error("E_CANARY_ACTIVE");
    const reason = assertText(args.reason, "release_reason", 500);
    const now = Date.now();
    const candidateId = await ctx.db.insert("releaseCandidates", { workspaceId: spec.workspaceId, agentSpecId: spec._id, targetVersion: args.targetVersion, status: "active", deterministicGatesPassed: 6, modelScore: args.modelScore, trafficPercent: args.trafficPercent, observations: 0, failures: 0, reason, createdAt: now });
    const fingerprint = await appendEvidence(ctx, spec.workspaceId, spec._id, "release.canary-started", `AgentSpec v${args.targetVersion} entered a ${args.trafficPercent}% canary after 6 deterministic gates and model score ${args.modelScore}.`, now);
    return { marker: "CANARY_STARTED" as const, candidateId, fingerprint };
  },
});

export const recordObservation = mutation({
  args: { candidateId: v.id("releaseCandidates"), failed: v.boolean() },
  handler: async (ctx, args) => {
    const candidate = await ctx.db.get(args.candidateId);
    if (!candidate || candidate.status !== "active") throw new Error("E_CANARY_NOT_ACTIVE");
    await requireWorkspaceRole(ctx, candidate.workspaceId, "operator");
    const observations = candidate.observations + 1;
    const failures = candidate.failures + (args.failed ? 1 : 0);
    await ctx.db.patch(candidate._id, { observations, failures });
    return { marker: "CANARY_OBSERVATION_RECORDED" as const, observations, failures };
  },
});

export const promoteCanary = mutation({
  args: { candidateId: v.id("releaseCandidates") },
  handler: async (ctx, args) => {
    const candidate = await ctx.db.get(args.candidateId);
    if (!candidate || candidate.status !== "active") throw new Error("E_CANARY_NOT_ACTIVE");
    await requireWorkspaceRole(ctx, candidate.workspaceId, "admin");
    if (candidate.observations < 20 || candidate.failures !== 0) throw new Error("E_CANARY_NOT_READY");
    const now = Date.now();
    await ctx.db.patch(candidate._id, { status: "promoted", completedAt: now });
    const fingerprint = await appendEvidence(ctx, candidate.workspaceId, candidate.agentSpecId, "release.canary-promoted", `AgentSpec v${candidate.targetVersion} promoted after ${candidate.observations} observations and 0 failures.`, now);
    return { marker: "CANARY_PROMOTED" as const, fingerprint };
  },
});

export const rollbackCanary = mutation({
  args: { candidateId: v.id("releaseCandidates"), reason: v.string() },
  handler: async (ctx, args) => {
    const candidate = await ctx.db.get(args.candidateId);
    if (!candidate || candidate.status !== "active") throw new Error("E_CANARY_NOT_ACTIVE");
    await requireWorkspaceRole(ctx, candidate.workspaceId, "admin");
    const reason = assertText(args.reason, "rollback_reason", 500);
    const now = Date.now();
    await ctx.db.patch(candidate._id, { status: "rolled-back", reason, completedAt: now });
    const fingerprint = await appendEvidence(ctx, candidate.workspaceId, candidate.agentSpecId, "release.canary-rolled-back", `AgentSpec v${candidate.targetVersion} canary rolled back: ${reason}`, now);
    return { marker: "CANARY_ROLLED_BACK" as const, fingerprint };
  },
});
