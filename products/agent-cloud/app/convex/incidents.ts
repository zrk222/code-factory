import { v } from "convex/values";
import type { Id } from "./_generated/dataModel";
import type { MutationCtx } from "./_generated/server";
import { mutation } from "./_generated/server";
import { assertText, receiptFingerprint } from "./domain";
import { requireWorkspaceRole } from "./access";

const recoveryCheck = v.union(v.literal("containment-verified"), v.literal("evidence-preserved"), v.literal("root-cause-recorded"), v.literal("rollback-verified"), v.literal("owner-approved"));

async function appendEvidence(ctx: MutationCtx, workspaceId: Id<"workspaces">, agentSpecId: Id<"agentSpecs">, event: string, detail: string, now: number) {
  const previous = await ctx.db.query("receipts").withIndex("by_workspace_created", (q) => q.eq("workspaceId", workspaceId)).order("desc").first();
  const fingerprint = receiptFingerprint([String(agentSpecId), event, detail, String(now)]);
  await ctx.db.insert("receipts", { workspaceId, agentSpecId, type: "incident-response", event, fingerprint, previousFingerprint: previous?.fingerprint, signatureState: "unsigned", createdAt: now });
  await ctx.db.insert("auditEvents", { workspaceId, actor: "incident-commander@factory.local", event, targetType: "agentSpec", targetId: String(agentSpecId), detail, createdAt: now });
  return fingerprint;
}

export const openIncident = mutation({
  args: { agentSpecId: v.id("agentSpecs"), severity: v.union(v.literal("sev1"), v.literal("sev2")), summary: v.string() },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "operator");
    const existing = await ctx.db.query("incidents").withIndex("by_agent_status", (q) => q.eq("agentSpecId", spec._id).eq("status", "contained")).unique();
    if (existing) throw new Error("E_INCIDENT_ACTIVE");
    const summary = assertText(args.summary, "incident_summary", 500);
    const now = Date.now();
    let closedRuns = 0; let closedApprovals = 0; let rolledBackCanaries = 0;
    const runs = await ctx.db.query("runs").withIndex("by_agent_started", (q) => q.eq("agentSpecId", spec._id)).collect();
    for (const run of runs.filter((item) => item.status === "awaiting-approval")) {
      await ctx.db.patch(run._id, { status: "blocked", completedAt: now }); closedRuns += 1;
      const approval = await ctx.db.query("approvals").withIndex("by_run", (q) => q.eq("runId", run._id)).unique();
      if (approval?.status === "pending") { await ctx.db.patch(approval._id, { status: "rejected", decidedBy: "incident-commander@factory.local", decidedAt: now, rationale: `Incident containment: ${summary}` }); closedApprovals += 1; }
    }
    const canaries = await ctx.db.query("releaseCandidates").withIndex("by_agent_status", (q) => q.eq("agentSpecId", spec._id).eq("status", "active")).collect();
    for (const canary of canaries) { await ctx.db.patch(canary._id, { status: "rolled-back", reason: `Incident containment: ${summary}`, completedAt: now }); rolledBackCanaries += 1; }
    const resumeEligible = spec.status === "active";
    if (resumeEligible) await ctx.db.patch(spec._id, { status: "suspended", updatedAt: now });
    const incidentId = await ctx.db.insert("incidents", { workspaceId: spec.workspaceId, agentSpecId: spec._id, severity: args.severity, status: "contained", summary, closedRuns, closedApprovals, rolledBackCanaries, resumeEligible, openedAt: now });
    const detail = `${args.severity} contained. Closed ${closedRuns} run(s), ${closedApprovals} approval(s), and rolled back ${rolledBackCanaries} canary release(s).`;
    const fingerprint = await appendEvidence(ctx, spec.workspaceId, spec._id, "incident.contained", detail, now);
    return { marker: "INCIDENT_CONTAINED" as const, authorityMarker: "INCIDENT_AUTHORITY_CLOSED" as const, canaryMarker: "INCIDENT_CANARY_ROLLED_BACK" as const, incidentId, closedRuns, closedApprovals, rolledBackCanaries, fingerprint };
  },
});

export const recordRecoveryCheck = mutation({
  args: { incidentId: v.id("incidents"), check: recoveryCheck },
  handler: async (ctx, args) => {
    const incident = await ctx.db.get(args.incidentId);
    if (!incident || incident.status !== "contained") throw new Error("E_INCIDENT_NOT_ACTIVE");
    await requireWorkspaceRole(ctx, incident.workspaceId, "operator");
    const existing = await ctx.db.query("incidentChecks").withIndex("by_incident_check", (q) => q.eq("incidentId", incident._id).eq("check", args.check)).unique();
    if (existing) throw new Error("E_RECOVERY_CHECK_DUPLICATE");
    const checkId = await ctx.db.insert("incidentChecks", { workspaceId: incident.workspaceId, incidentId: incident._id, check: args.check, completedBy: "incident-commander@factory.local", completedAt: Date.now() });
    return { marker: "RECOVERY_CHECK_RECORDED" as const, checkId };
  },
});

export const resolveIncident = mutation({
  args: { incidentId: v.id("incidents"), resolutionNote: v.string() },
  handler: async (ctx, args) => {
    const incident = await ctx.db.get(args.incidentId);
    if (!incident || incident.status !== "contained") throw new Error("E_INCIDENT_NOT_ACTIVE");
    await requireWorkspaceRole(ctx, incident.workspaceId, "operator");
    const checks = await ctx.db.query("incidentChecks").withIndex("by_incident_check", (q) => q.eq("incidentId", incident._id)).collect();
    if (checks.length !== 5) throw new Error("E_RECOVERY_INCOMPLETE");
    const note = assertText(args.resolutionNote, "resolution_note", 500);
    const spec = await ctx.db.get(incident.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    if (spec.status === "revoked") throw new Error("E_AGENT_REVOKED");
    const now = Date.now();
    if (incident.resumeEligible && spec.status === "suspended") await ctx.db.patch(spec._id, { status: "active", updatedAt: now });
    await ctx.db.patch(incident._id, { status: "resolved", resolutionNote: note, resolvedAt: now });
    const fingerprint = await appendEvidence(ctx, incident.workspaceId, incident.agentSpecId, "incident.resolved", `Recovery runbook completed with 5 checks: ${note}`, now);
    return { marker: "INCIDENT_RESOLVED" as const, checks: checks.length, agentStatus: incident.resumeEligible ? "active" as const : spec.status, fingerprint };
  },
});
