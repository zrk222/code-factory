import { v } from "convex/values";
import type { Id } from "./_generated/dataModel";
import type { MutationCtx, QueryCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import { requireOrganizationRole } from "./enterpriseIdentity";
import { assertIntegerRange, assertText, validateSecretReference } from "./domain";

const scope = v.union(v.literal("workspace"), v.literal("agent"), v.literal("subject"));

async function ownedWorkspace(ctx: MutationCtx | QueryCtx, organizationId: Id<"organizations">, workspaceId: Id<"workspaces">) {
  const workspace = await ctx.db.get(workspaceId);
  if (!workspace || workspace.organizationId !== organizationId) throw new Error("E_CROSS_ORGANIZATION_WORKSPACE");
  return workspace;
}

/** Enforces one residency, encryption, retention, and recovery contract per workspace. */
export const configurePolicy = mutation({
  args: { organizationId: v.id("organizations"), workspaceId: v.id("workspaces"), residencyRegion: v.string(), backupRegion: v.string(), kmsKeyRef: v.string(), retentionDays: v.number(), rtoMinutes: v.number(), rpoMinutes: v.number(), enforce: v.boolean() },
  handler: async (ctx, args) => {
    const authorized = await requireOrganizationRole(ctx, args.organizationId, "admin");
    await ownedWorkspace(ctx, args.organizationId, args.workspaceId);
    assertIntegerRange(args.retentionDays, "retention_days", 1, 3650);
    assertIntegerRange(args.rtoMinutes, "rto_minutes", 1, 10080);
    assertIntegerRange(args.rpoMinutes, "rpo_minutes", 0, 1440);
    const residencyRegion = assertText(args.residencyRegion, "residency_region", 80);
    const backupRegion = assertText(args.backupRegion, "backup_region", 80);
    if (residencyRegion === backupRegion) throw new Error("E_BACKUP_FAILURE_DOMAIN_NOT_SEPARATE");
    const record = { organizationId: args.organizationId, workspaceId: args.workspaceId, residencyRegion, backupRegion, kmsKeyRef: validateSecretReference(args.kmsKeyRef), retentionDays: args.retentionDays, rtoMinutes: args.rtoMinutes, rpoMinutes: args.rpoMinutes, status: args.enforce ? "enforced" as const : "draft" as const, updatedAt: Date.now() };
    const existing = await ctx.db.query("enterprisePolicies").withIndex("by_workspace", (q) => q.eq("workspaceId", args.workspaceId)).unique();
    const policyId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("enterprisePolicies", record);
    await ctx.db.insert("auditEvents", { workspaceId: args.workspaceId, actor: authorized.tokenIdentifier, event: "enterprise.governance-policy-configured", targetType: "enterprisePolicy", targetId: String(policyId), detail: `Residency ${residencyRegion}; backup failure domain ${backupRegion}; key stored by reference only.`, createdAt: Date.now() });
    return { marker: "ENTERPRISE_GOVERNANCE_POLICY_CONFIGURED" as const, policyId, status: record.status, keyMarker: "CUSTOMER_MANAGED_KEY_REFERENCE_ONLY" as const };
  },
});

/** Places an auditable hold that blocks overlapping deletion requests. */
export const placeLegalHold = mutation({
  args: { organizationId: v.id("organizations"), workspaceId: v.id("workspaces"), scope, scopeKey: v.string(), reason: v.string() },
  handler: async (ctx, args) => {
    const authorized = await requireOrganizationRole(ctx, args.organizationId, "admin");
    await ownedWorkspace(ctx, args.organizationId, args.workspaceId);
    const scopeKey = assertText(args.scopeKey, "scope_key", 240);
    const existing = await ctx.db.query("legalHolds").withIndex("by_workspace_scope", (q) => q.eq("workspaceId", args.workspaceId).eq("scope", args.scope).eq("scopeKey", scopeKey)).collect();
    if (existing.some((hold) => hold.status === "active")) throw new Error("E_LEGAL_HOLD_EXISTS");
    const holdId = await ctx.db.insert("legalHolds", { organizationId: args.organizationId, workspaceId: args.workspaceId, scope: args.scope, scopeKey, reason: assertText(args.reason, "legal_hold_reason", 1000), status: "active", placedBy: authorized.tokenIdentifier, placedAt: Date.now() });
    return { marker: "ENTERPRISE_LEGAL_HOLD_PLACED" as const, holdId };
  },
});

/** Releases a hold but preserves the record and actor trail. */
export const releaseLegalHold = mutation({
  args: { organizationId: v.id("organizations"), holdId: v.id("legalHolds") },
  handler: async (ctx, args) => {
    const authorized = await requireOrganizationRole(ctx, args.organizationId, "admin");
    const hold = await ctx.db.get(args.holdId);
    if (!hold || hold.organizationId !== args.organizationId) throw new Error("E_LEGAL_HOLD_NOT_FOUND");
    if (hold.status !== "active") throw new Error("E_LEGAL_HOLD_NOT_ACTIVE");
    await ctx.db.patch(hold._id, { status: "released", releasedBy: authorized.tokenIdentifier, releasedAt: Date.now() });
    return { marker: "ENTERPRISE_LEGAL_HOLD_RELEASED" as const };
  },
});

/** Admits deletion only when no workspace-wide or exact-scope legal hold applies. */
export const requestDeletion = mutation({
  args: { organizationId: v.id("organizations"), workspaceId: v.id("workspaces"), scope, scopeKey: v.string(), reason: v.string() },
  handler: async (ctx, args) => {
    const authorized = await requireOrganizationRole(ctx, args.organizationId, "admin");
    await ownedWorkspace(ctx, args.organizationId, args.workspaceId);
    const scopeKey = assertText(args.scopeKey, "scope_key", 240);
    const activeHolds = await ctx.db.query("legalHolds").withIndex("by_workspace_status", (q) => q.eq("workspaceId", args.workspaceId).eq("status", "active")).collect();
    const blocked = activeHolds.some((hold) => hold.scope === "workspace" || (hold.scope === args.scope && hold.scopeKey === scopeKey));
    const status = blocked ? "blocked-by-legal-hold" as const : "approved-for-execution" as const;
    const deletionRequestId = await ctx.db.insert("deletionRequests", { organizationId: args.organizationId, workspaceId: args.workspaceId, scope: args.scope, scopeKey, reason: assertText(args.reason, "deletion_reason", 1000), status, requestedBy: authorized.tokenIdentifier, requestedAt: Date.now() });
    return { marker: "ENTERPRISE_DELETION_REQUESTED" as const, deletionRequestId, status };
  },
});

/** Exposes sanitized governance posture to organization auditors. */
export const posture = query({
  args: { organizationId: v.id("organizations"), workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    await requireOrganizationRole(ctx, args.organizationId, "auditor");
    await ownedWorkspace(ctx, args.organizationId, args.workspaceId);
    const [policy, holds, deletions] = await Promise.all([
      ctx.db.query("enterprisePolicies").withIndex("by_workspace", (q) => q.eq("workspaceId", args.workspaceId)).unique(),
      ctx.db.query("legalHolds").withIndex("by_workspace_status", (q) => q.eq("workspaceId", args.workspaceId).eq("status", "active")).collect(),
      ctx.db.query("deletionRequests").withIndex("by_workspace_requested", (q) => q.eq("workspaceId", args.workspaceId)).collect(),
    ]);
    return { marker: "ENTERPRISE_GOVERNANCE_POSTURE" as const, policy: policy ? { residencyRegion: policy.residencyRegion, backupRegion: policy.backupRegion, retentionDays: policy.retentionDays, rtoMinutes: policy.rtoMinutes, rpoMinutes: policy.rpoMinutes, status: policy.status, keyConfigured: true } : null, activeLegalHolds: holds.length, deletionRequests: deletions.map((item) => ({ scope: item.scope, status: item.status, requestedAt: item.requestedAt })) };
  },
});
