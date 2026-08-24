import { v } from "convex/values";
import type { Id } from "./_generated/dataModel";
import type { MutationCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";
import { requireOrganizationRole } from "./enterpriseIdentity";
import { assertIntegerRange, assertText } from "./domain";

/** Atomically admits one request under the workspace route and concurrency policy. */
export async function consumeAdmission(ctx: MutationCtx, workspaceId: Id<"workspaces">, route: string) {
  const policy = await ctx.db.query("admissionPolicies").withIndex("by_workspace_route", (q) => q.eq("workspaceId", workspaceId).eq("route", route)).unique();
  if (!policy || policy.status !== "enforced") return { marker: "ADMISSION_POLICY_NOT_ENFORCED" as const };
  const running = await ctx.db.query("executionJobs").withIndex("by_workspace_status_created", (q) => q.eq("workspaceId", workspaceId).eq("status", "running")).collect();
  if (running.length >= policy.maxConcurrentRuns) throw new Error("E_CONCURRENCY_LIMIT_REACHED");
  const now = Date.now();
  const windowMs = policy.windowSeconds * 1000;
  const existing = await ctx.db.query("admissionWindows").withIndex("by_workspace_route", (q) => q.eq("workspaceId", workspaceId).eq("route", route)).unique();
  const inWindow = existing && now - existing.windowStart < windowMs;
  const count = inWindow ? existing.count : 0;
  if (count >= policy.maxRequests) throw new Error("E_RATE_LIMIT_REACHED");
  if (existing) await ctx.db.patch(existing._id, { windowStart: inWindow ? existing.windowStart : now, count: count + 1, updatedAt: now });
  else await ctx.db.insert("admissionWindows", { workspaceId, route, windowStart: now, count: 1, updatedAt: now });
  return { marker: "REQUEST_ADMITTED" as const, remaining: policy.maxRequests - count - 1 };
}

/** Configures fail-closed hosted execution admission for an enterprise workspace. */
export const configureAdmission = mutation({
  args: { organizationId: v.id("organizations"), workspaceId: v.id("workspaces"), maxRequests: v.number(), windowSeconds: v.number(), maxConcurrentRuns: v.number(), enforce: v.boolean() },
  handler: async (ctx, args) => {
    const authorized = await requireOrganizationRole(ctx, args.organizationId, "admin");
    const workspace = await ctx.db.get(args.workspaceId);
    if (!workspace || workspace.organizationId !== args.organizationId) throw new Error("E_CROSS_ORGANIZATION_WORKSPACE");
    assertIntegerRange(args.maxRequests, "max_requests", 1, 100000);
    assertIntegerRange(args.windowSeconds, "window_seconds", 1, 86400);
    assertIntegerRange(args.maxConcurrentRuns, "max_concurrent_runs", 1, 10000);
    const route = "execution.enqueue";
    const record = { organizationId: args.organizationId, workspaceId: args.workspaceId, route, maxRequests: args.maxRequests, windowSeconds: args.windowSeconds, maxConcurrentRuns: args.maxConcurrentRuns, status: args.enforce ? "enforced" as const : "monitor" as const, updatedAt: Date.now() };
    const existing = await ctx.db.query("admissionPolicies").withIndex("by_workspace_route", (q) => q.eq("workspaceId", args.workspaceId).eq("route", route)).unique();
    const policyId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("admissionPolicies", record);
    await ctx.db.insert("auditEvents", { workspaceId: args.workspaceId, actor: authorized.tokenIdentifier, event: "enterprise.admission-policy-configured", targetType: "admissionPolicy", targetId: String(policyId), detail: `${record.status}; ${args.maxRequests}/${args.windowSeconds}s; ${args.maxConcurrentRuns} concurrent.`, createdAt: Date.now() });
    return { marker: "ENTERPRISE_ADMISSION_CONFIGURED" as const, policyId, status: record.status };
  },
});

/** Returns an evidence-oriented release posture, never secrets or identity claims. */
export const qualification = query({
  args: { organizationId: v.id("organizations"), workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    await requireOrganizationRole(ctx, args.organizationId, "auditor");
    await requireWorkspaceRole(ctx, args.workspaceId, "viewer");
    const workspace = await ctx.db.get(args.workspaceId);
    if (!workspace || workspace.organizationId !== args.organizationId) throw new Error("E_CROSS_ORGANIZATION_WORKSPACE");
    const [identityDirectories, governance, admission, backups, drills] = await Promise.all([
      ctx.db.query("directoryConnections").withIndex("by_org_protocol", (q) => q.eq("organizationId", args.organizationId)).collect(),
      ctx.db.query("enterprisePolicies").withIndex("by_workspace", (q) => q.eq("workspaceId", args.workspaceId)).unique(),
      ctx.db.query("admissionPolicies").withIndex("by_workspace_route", (q) => q.eq("workspaceId", args.workspaceId).eq("route", "execution.enqueue")).unique(),
      ctx.db.query("backupSnapshots").withIndex("by_workspace_requested", (q) => q.eq("workspaceId", args.workspaceId)).order("desc").take(10),
      ctx.db.query("restoreDrills").withIndex("by_workspace_requested", (q) => q.eq("workspaceId", args.workspaceId)).order("desc").take(10),
    ]);
    const checks = {
      directoryActivated: identityDirectories.some((item) => item.status === "active"),
      governanceEnforced: governance?.status === "enforced",
      admissionEnforced: admission?.status === "enforced",
      backupVerified: backups.some((item) => item.state === "completed"),
      restoreVerified: drills.some((item) => item.state === "passed"),
    };
    return { marker: "ENTERPRISE_RELEASE_QUALIFICATION" as const, qualified: Object.values(checks).every(Boolean), checks };
  },
});
