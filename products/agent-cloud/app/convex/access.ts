import { v } from "convex/values";
import type { Id } from "./_generated/dataModel";
import type { MutationCtx, QueryCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import { assertText, receiptFingerprint } from "./domain";

const requestedRole = v.union(v.literal("owner"), v.literal("admin"), v.literal("operator"), v.literal("reviewer"), v.literal("viewer"));
type AccessCtx = MutationCtx | QueryCtx;
type WorkspaceRole = "owner" | "admin" | "operator" | "reviewer" | "viewer";

const roleRank: Record<WorkspaceRole, number> = { owner: 5, admin: 4, operator: 3, reviewer: 2, viewer: 1 };

export async function principal(ctx: AccessCtx) {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) throw new Error("E_AUTH_REQUIRED");
  return { tokenIdentifier: identity.tokenIdentifier, marker: "IDENTITY_PRINCIPAL_DERIVED" as const };
}

/** Resolves an authenticated active membership and enforces a minimum role. */
export async function requireWorkspaceRole(ctx: AccessCtx, workspaceId: Id<"workspaces">, minimumRole: WorkspaceRole) {
  const derived = await principal(ctx);
  const membership = await ctx.db
    .query("workspaceMemberships")
    .withIndex("by_workspace_subject", (q) => q.eq("workspaceId", workspaceId).eq("tokenIdentifier", derived.tokenIdentifier))
    .unique();
  if (!membership || membership.status !== "active") throw new Error("E_WORKSPACE_ACCESS_DENIED");
  if (roleRank[membership.role] < roleRank[minimumRole]) throw new Error("E_ROLE_FORBIDDEN");
  return { ...derived, membership };
}

export async function appendIdentityEvidence(
  ctx: MutationCtx,
  workspaceId: Id<"workspaces">,
  membershipId: Id<"workspaceMemberships">,
  event: "identity.owner-bootstrapped" | "identity.member-added" | "identity.member-revoked",
  role: WorkspaceRole,
  now: number,
) {
  const previous = await ctx.db.query("receipts").withIndex("by_workspace_created", (q) => q.eq("workspaceId", workspaceId)).order("desc").first();
  const fingerprint = receiptFingerprint([String(workspaceId), String(membershipId), event, role, String(now)]);
  await ctx.db.insert("receipts", {
    workspaceId,
    workspaceMembershipId: membershipId,
    type: "identity-access",
    event,
    fingerprint,
    previousFingerprint: previous?.fingerprint,
    signatureState: "unsigned",
    createdAt: now,
  });
  await ctx.db.insert("auditEvents", {
    workspaceId,
    actor: "identity-gateway@factory.local",
    event,
    targetType: "workspaceMembership",
    targetId: String(membershipId),
    detail: `Membership transition recorded for role ${role}; sensitive identity and contact fields omitted.`,
    createdAt: now,
  });
  return fingerprint;
}

/** Lets the first authenticated principal claim an empty local workspace exactly once. */
export const bootstrapOwner = mutation({
  args: { workspaceId: v.id("workspaces"), memberLabel: v.string() },
  handler: async (ctx, args) => {
    const derived = await principal(ctx);
    const memberLabel = assertText(args.memberLabel, "member_label", 240);
    const workspace = await ctx.db.get(args.workspaceId);
    if (!workspace) throw new Error("E_WORKSPACE_NOT_FOUND");
    const memberships = await ctx.db.query("workspaceMemberships").withIndex("by_workspace_status", (q) => q.eq("workspaceId", workspace._id)).collect();
    if (memberships.length !== 0) throw new Error("E_BOOTSTRAP_CLOSED");
    const now = Date.now();
    const membershipId = await ctx.db.insert("workspaceMemberships", {
      workspaceId: workspace._id,
      tokenIdentifier: derived.tokenIdentifier,
      memberLabel,
      role: "owner",
      status: "active",
      createdBy: "authenticated-bootstrap",
      createdAt: now,
    });
    const fingerprint = await appendIdentityEvidence(ctx, workspace._id, membershipId, "identity.owner-bootstrapped", "owner", now);
    return { marker: "WORKSPACE_OWNER_BOOTSTRAPPED" as const, principalMarker: derived.marker, evidenceMarker: "IDENTITY_EVIDENCE_REDACTED" as const, membershipId, fingerprint };
  },
});

/** Adds a non-owner member after server-side owner authorization. */
export const addMember = mutation({
  args: { workspaceId: v.id("workspaces"), tokenIdentifier: v.string(), memberLabel: v.string(), role: requestedRole },
  handler: async (ctx, args) => {
    const authorized = await requireWorkspaceRole(ctx, args.workspaceId, "owner");
    if (args.role === "owner") throw new Error("E_OWNER_ASSIGNMENT_FORBIDDEN");
    const tokenIdentifier = assertText(args.tokenIdentifier, "token_identifier", 240);
    const memberLabel = assertText(args.memberLabel, "member_label", 240);
    const existing = await ctx.db.query("workspaceMemberships").withIndex("by_workspace_subject", (q) => q.eq("workspaceId", args.workspaceId).eq("tokenIdentifier", tokenIdentifier)).unique();
    if (existing) throw new Error("E_MEMBERSHIP_EXISTS");
    const now = Date.now();
    const membershipId = await ctx.db.insert("workspaceMemberships", {
      workspaceId: args.workspaceId,
      tokenIdentifier,
      memberLabel,
      role: args.role,
      status: "active",
      createdBy: authorized.tokenIdentifier,
      createdAt: now,
    });
    const fingerprint = await appendIdentityEvidence(ctx, args.workspaceId, membershipId, "identity.member-added", args.role, now);
    return { marker: "WORKSPACE_MEMBER_ADDED" as const, principalMarker: authorized.marker, evidenceMarker: "IDENTITY_EVIDENCE_REDACTED" as const, membershipId, fingerprint };
  },
});

/** Revokes a member while preserving at least one active workspace owner. */
export const revokeMember = mutation({
  args: { membershipId: v.id("workspaceMemberships"), reason: v.string() },
  handler: async (ctx, args) => {
    const membership = await ctx.db.get(args.membershipId);
    if (!membership) throw new Error("E_MEMBERSHIP_NOT_FOUND");
    await requireWorkspaceRole(ctx, membership.workspaceId, "owner");
    if (membership.status !== "active") throw new Error("E_MEMBERSHIP_NOT_ACTIVE");
    const reason = assertText(args.reason, "reason", 500);
    if (membership.role === "owner") {
      const active = await ctx.db.query("workspaceMemberships").withIndex("by_workspace_status", (q) => q.eq("workspaceId", membership.workspaceId).eq("status", "active")).collect();
      if (active.filter((item) => item.role === "owner").length <= 1) throw new Error("E_LAST_OWNER_REQUIRED");
    }
    const now = Date.now();
    await ctx.db.patch(membership._id, { status: "revoked", revokedAt: now, revocationReason: reason });
    const fingerprint = await appendIdentityEvidence(ctx, membership.workspaceId, membership._id, "identity.member-revoked", membership.role, now);
    return { marker: "WORKSPACE_MEMBER_REVOKED" as const, evidenceMarker: "IDENTITY_EVIDENCE_REDACTED" as const, fingerprint };
  },
});

/** Explains the caller's membership without returning authentication claims. */
export const myAccess = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    const authorized = await requireWorkspaceRole(ctx, args.workspaceId, "viewer");
    return {
      marker: "WORKSPACE_ACCESS_EXPLAINED" as const,
      principalMarker: authorized.marker,
      workspaceId: args.workspaceId,
      memberLabel: authorized.membership.memberLabel,
      role: authorized.membership.role,
      status: authorized.membership.status,
    };
  },
});

/** Lists only active workspaces derived from the authenticated principal. */
export const myWorkspaces = query({
  args: {},
  handler: async (ctx) => {
    const derived = await principal(ctx);
    const memberships = await ctx.db
      .query("workspaceMemberships")
      .withIndex("by_subject_status", (q) => q.eq("tokenIdentifier", derived.tokenIdentifier).eq("status", "active"))
      .collect();
    const workspaces = await Promise.all(memberships.map(async (membership) => {
      const workspace = await ctx.db.get(membership.workspaceId);
      return workspace ? { workspace, role: membership.role, memberLabel: membership.memberLabel } : null;
    }));
    return { marker: "AUTHENTICATED_WORKSPACES_DERIVED" as const, workspaces: workspaces.filter((item) => item !== null) };
  },
});

/** Reads one AgentSpec only after membership and resource ownership checks. */
export const readAgentSpec = query({
  args: { workspaceId: v.id("workspaces"), agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const authorized = await requireWorkspaceRole(ctx, args.workspaceId, "viewer");
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    if (spec.workspaceId !== args.workspaceId) throw new Error("E_CROSS_TENANT_RESOURCE");
    return { marker: "WORKSPACE_RESOURCE_AUTHORIZED" as const, principalMarker: authorized.marker, spec };
  },
});
