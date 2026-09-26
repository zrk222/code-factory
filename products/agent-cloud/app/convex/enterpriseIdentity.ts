import { v } from "convex/values";
import type { Id } from "./_generated/dataModel";
import type { MutationCtx, QueryCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import { principal, requireWorkspaceRole } from "./access";
import { assertText, validateSecretReference } from "./domain";

type OrgRole = "owner" | "admin" | "auditor";
const orgRank: Record<OrgRole, number> = { owner: 3, admin: 2, auditor: 1 };

export async function requireOrganizationRole(ctx: MutationCtx | QueryCtx, organizationId: Id<"organizations">, minimum: OrgRole) {
  const derived = await principal(ctx);
  const membership = await ctx.db.query("organizationMemberships")
    .withIndex("by_org_subject", (q) => q.eq("organizationId", organizationId).eq("tokenIdentifier", derived.tokenIdentifier)).unique();
  if (!membership || membership.status !== "active") throw new Error("E_ORGANIZATION_ACCESS_DENIED");
  if (orgRank[membership.role] < orgRank[minimum]) throw new Error("E_ORGANIZATION_ROLE_FORBIDDEN");
  const organization = await ctx.db.get(organizationId);
  if (!organization || organization.status !== "active") throw new Error("E_ORGANIZATION_SUSPENDED");
  return { ...derived, membership, organization };
}

async function audit(ctx: MutationCtx, workspaceId: Id<"workspaces">, actor: string, event: string, targetId: string, detail: string) {
  await ctx.db.insert("auditEvents", { workspaceId, actor, event, targetType: "enterprise-identity", targetId, detail, createdAt: Date.now() });
}

/** Creates an organization around a workspace whose caller is already an owner. */
export const createOrganization = mutation({
  args: { workspaceId: v.id("workspaces"), slug: v.string(), name: v.string(), ownerLabel: v.string() },
  handler: async (ctx, args) => {
    const authorized = await requireWorkspaceRole(ctx, args.workspaceId, "owner");
    const workspace = await ctx.db.get(args.workspaceId);
    if (!workspace) throw new Error("E_WORKSPACE_NOT_FOUND");
    if (workspace.organizationId) throw new Error("E_WORKSPACE_ALREADY_ORGANIZED");
    const slug = assertText(args.slug, "organization_slug", 80).toLowerCase();
    if (!/^[a-z0-9][a-z0-9-]*$/.test(slug)) throw new Error("E_INVALID_ORGANIZATION_SLUG");
    if (await ctx.db.query("organizations").withIndex("by_slug", (q) => q.eq("slug", slug)).unique()) throw new Error("E_ORGANIZATION_SLUG_EXISTS");
    const now = Date.now();
    const organizationId = await ctx.db.insert("organizations", { slug, name: assertText(args.name, "organization_name", 160), status: "active", createdAt: now });
    await ctx.db.insert("organizationMemberships", { organizationId, tokenIdentifier: authorized.tokenIdentifier, memberLabel: assertText(args.ownerLabel, "owner_label", 160), role: "owner", status: "active", createdAt: now });
    await ctx.db.patch(workspace._id, { organizationId });
    await audit(ctx, workspace._id, authorized.tokenIdentifier, "enterprise.organization-created", String(organizationId), "Organization boundary created and workspace attached.");
    return { marker: "ENTERPRISE_ORGANIZATION_CREATED" as const, organizationId };
  },
});

/** Delegates bounded organization administration without granting workspace ownership. */
export const addOrganizationAdmin = mutation({
  args: { organizationId: v.id("organizations"), workspaceId: v.id("workspaces"), tokenIdentifier: v.string(), memberLabel: v.string(), role: v.union(v.literal("admin"), v.literal("auditor")) },
  handler: async (ctx, args) => {
    const authorized = await requireOrganizationRole(ctx, args.organizationId, "owner");
    const workspace = await ctx.db.get(args.workspaceId);
    if (!workspace || workspace.organizationId !== args.organizationId) throw new Error("E_CROSS_ORGANIZATION_WORKSPACE");
    const tokenIdentifier = assertText(args.tokenIdentifier, "token_identifier", 240);
    if (await ctx.db.query("organizationMemberships").withIndex("by_org_subject", (q) => q.eq("organizationId", args.organizationId).eq("tokenIdentifier", tokenIdentifier)).unique()) throw new Error("E_ORGANIZATION_MEMBERSHIP_EXISTS");
    const membershipId = await ctx.db.insert("organizationMemberships", { organizationId: args.organizationId, tokenIdentifier, memberLabel: assertText(args.memberLabel, "member_label", 160), role: args.role, status: "active", createdAt: Date.now() });
    await audit(ctx, workspace._id, authorized.tokenIdentifier, "enterprise.admin-delegated", String(membershipId), `Delegated organization role ${args.role}; no workspace owner role granted.`);
    return { marker: "ENTERPRISE_ADMIN_DELEGATED" as const, membershipId };
  },
});

/** Stores tenant SSO/SCIM metadata and an opaque credential reference, never a bearer secret. */
export const configureDirectory = mutation({
  args: { organizationId: v.id("organizations"), workspaceId: v.id("workspaces"), protocol: v.union(v.literal("scim-2.0"), v.literal("oidc"), v.literal("saml-2.0")), issuer: v.string(), tenantKey: v.string(), secretRef: v.string(), defaultWorkspaceRole: v.union(v.literal("admin"), v.literal("operator"), v.literal("reviewer"), v.literal("viewer")) },
  handler: async (ctx, args) => {
    const authorized = await requireOrganizationRole(ctx, args.organizationId, "admin");
    const workspace = await ctx.db.get(args.workspaceId);
    if (!workspace || workspace.organizationId !== args.organizationId) throw new Error("E_CROSS_ORGANIZATION_WORKSPACE");
    const existing = await ctx.db.query("directoryConnections").withIndex("by_org_protocol", (q) => q.eq("organizationId", args.organizationId).eq("protocol", args.protocol)).unique();
    const record = { issuer: assertText(args.issuer, "directory_issuer", 300), tenantKey: assertText(args.tenantKey, "tenant_key", 120), secretRef: validateSecretReference(args.secretRef), defaultWorkspaceRole: args.defaultWorkspaceRole, status: "setup-required" as const, updatedAt: Date.now() };
    const directoryConnectionId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("directoryConnections", { organizationId: args.organizationId, protocol: args.protocol, ...record });
    await audit(ctx, workspace._id, authorized.tokenIdentifier, "enterprise.directory-configured", String(directoryConnectionId), `${args.protocol} metadata recorded; external tenant validation remains required.`);
    return { marker: "ENTERPRISE_DIRECTORY_CONFIGURED" as const, directoryConnectionId, status: "setup-required" as const, credentialMarker: "OPAQUE_SECRET_REFERENCE_ONLY" as const };
  },
});

/** Applies an idempotent directory identity to one organization-owned workspace. */
export const provisionWorkspaceMember = mutation({
  args: { organizationId: v.id("organizations"), directoryConnectionId: v.id("directoryConnections"), workspaceId: v.id("workspaces"), externalId: v.string(), tokenIdentifier: v.string(), memberLabel: v.string() },
  handler: async (ctx, args) => {
    const authorized = await requireOrganizationRole(ctx, args.organizationId, "admin");
    const [workspace, directory] = await Promise.all([ctx.db.get(args.workspaceId), ctx.db.get(args.directoryConnectionId)]);
    if (!workspace || workspace.organizationId !== args.organizationId || !directory || directory.organizationId !== args.organizationId) throw new Error("E_CROSS_ORGANIZATION_DIRECTORY");
    if (directory.status === "disabled") throw new Error("E_DIRECTORY_DISABLED");
    const externalId = assertText(args.externalId, "external_id", 240);
    const priorEvent = await ctx.db.query("directoryProvisioningEvents").withIndex("by_connection_external", (q) => q.eq("directoryConnectionId", directory._id).eq("externalId", externalId)).order("desc").first();
    if (priorEvent) return { marker: "ENTERPRISE_MEMBER_PROVISIONED" as const, membershipId: priorEvent.membershipId, idempotent: true };
    const tokenIdentifier = assertText(args.tokenIdentifier, "token_identifier", 240);
    const existing = await ctx.db.query("workspaceMemberships").withIndex("by_workspace_subject", (q) => q.eq("workspaceId", workspace._id).eq("tokenIdentifier", tokenIdentifier)).unique();
    if (existing && existing.directoryExternalId !== externalId) throw new Error("E_IDENTITY_COLLISION");
    const now = Date.now();
    const membershipId = existing ? (await ctx.db.patch(existing._id, { memberLabel: assertText(args.memberLabel, "member_label", 160), role: directory.defaultWorkspaceRole, status: "active", directoryExternalId: externalId }), existing._id) : await ctx.db.insert("workspaceMemberships", { workspaceId: workspace._id, tokenIdentifier, memberLabel: assertText(args.memberLabel, "member_label", 160), role: directory.defaultWorkspaceRole, status: "active", createdBy: "enterprise-directory", directoryExternalId: externalId, createdAt: now });
    await ctx.db.insert("directoryProvisioningEvents", { organizationId: args.organizationId, directoryConnectionId: directory._id, workspaceId: workspace._id, externalId, operation: existing ? "update" : "provision", membershipId, actor: authorized.tokenIdentifier, createdAt: now });
    await audit(ctx, workspace._id, authorized.tokenIdentifier, "enterprise.member-provisioned", String(membershipId), `Directory role mapping applied as ${directory.defaultWorkspaceRole}.`);
    return { marker: "ENTERPRISE_MEMBER_PROVISIONED" as const, membershipId, idempotent: false };
  },
});

/** Returns sanitized enterprise identity posture without identity claims or secret references. */
export const posture = query({
  args: { organizationId: v.id("organizations"), workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    const authorized = await requireOrganizationRole(ctx, args.organizationId, "auditor");
    const workspace = await ctx.db.get(args.workspaceId);
    if (!workspace || workspace.organizationId !== args.organizationId) throw new Error("E_CROSS_ORGANIZATION_WORKSPACE");
    const [members, directories, events] = await Promise.all([
      ctx.db.query("organizationMemberships").collect(),
      ctx.db.query("directoryConnections").withIndex("by_org_protocol", (q) => q.eq("organizationId", args.organizationId)).collect(),
      ctx.db.query("directoryProvisioningEvents").withIndex("by_org_created", (q) => q.eq("organizationId", args.organizationId)).collect(),
    ]);
    return { marker: "ENTERPRISE_IDENTITY_POSTURE" as const, organization: { name: authorized.organization.name, status: authorized.organization.status }, activeDelegates: members.filter((member) => member.organizationId === args.organizationId && member.status === "active").length, directories: directories.map((item) => ({ protocol: item.protocol, issuer: item.issuer, status: item.status, defaultWorkspaceRole: item.defaultWorkspaceRole })), provisioningEventCount: events.length };
  },
});
