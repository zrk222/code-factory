import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";
import { assertText, validateSecretReference } from "./domain";

const provider = v.union(v.literal("google-drive"), v.literal("onedrive"), v.literal("sharepoint"), v.literal("notion"), v.literal("dropbox"), v.literal("confluence"), v.literal("web"), v.literal("s3"), v.literal("azure-blob"), v.literal("github"), v.literal("database"));
const syncMode = v.union(v.literal("manual"), v.literal("daily"), v.literal("weekly"));

function safeLocator(value: string) {
  const locator = assertText(value, "source_locator", 500);
  if (/\/\/[^/\s]+:[^/@\s]+@/i.test(locator) || /[?&](?:token|key|secret|password)=/i.test(locator)) throw new Error("E_CONNECTOR_CREDENTIAL_IN_LOCATOR");
  return locator;
}

/** Saves a credential-free knowledge connector definition for later OAuth or secret-ref activation. */
export const configure = mutation({
  args: { workspaceId: v.id("workspaces"), agentSpecId: v.id("agentSpecs"), provider, label: v.string(), sourceLocator: v.string(), secretRef: v.optional(v.string()), syncMode },
  handler: async (ctx, args) => {
    await requireWorkspaceRole(ctx, args.workspaceId, "admin");
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec || spec.workspaceId !== args.workspaceId) throw new Error("E_CROSS_TENANT_RESOURCE");
    const label = assertText(args.label, "connector_label", 100);
    const sourceLocator = safeLocator(args.sourceLocator);
    const secretRef = args.secretRef ? validateSecretReference(args.secretRef) : undefined;
    const existing = await ctx.db.query("knowledgeConnectors").withIndex("by_agent_provider", (q) => q.eq("agentSpecId", spec._id).eq("provider", args.provider)).unique();
    const record = { workspaceId: args.workspaceId, agentSpecId: spec._id, provider: args.provider, label, sourceLocator, secretRef, syncMode: args.syncMode, status: "setup-required" as const, updatedAt: Date.now() };
    const connectorId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("knowledgeConnectors", record);
    await ctx.db.insert("auditEvents", { workspaceId: args.workspaceId, actor: "knowledge-connector@factory.local", event: "knowledge-connector.configured", targetType: "knowledgeConnector", targetId: String(connectorId), detail: `${args.provider} source definition saved without raw credentials; activation still requires tenant authorization.`, createdAt: record.updatedAt });
    return { marker: "KNOWLEDGE_CONNECTOR_CONFIGURED" as const, credentialMarker: "RAW_CREDENTIAL_ABSENT" as const, connectorId, status: record.status };
  },
});

/** Lists connector metadata only after workspace membership authorization. */
export const list = query({
  args: { workspaceId: v.id("workspaces"), agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    await requireWorkspaceRole(ctx, args.workspaceId, "viewer");
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec || spec.workspaceId !== args.workspaceId) throw new Error("E_CROSS_TENANT_RESOURCE");
    return ctx.db.query("knowledgeConnectors").withIndex("by_agent_provider", (q) => q.eq("agentSpecId", spec._id)).collect();
  },
});

/** Disables future sync attempts without deleting its audit history. */
export const disable = mutation({
  args: { connectorId: v.id("knowledgeConnectors") },
  handler: async (ctx, args) => {
    const connector = await ctx.db.get(args.connectorId);
    if (!connector) throw new Error("E_CONNECTOR_NOT_FOUND");
    await requireWorkspaceRole(ctx, connector.workspaceId, "admin");
    await ctx.db.patch(connector._id, { status: "disabled", updatedAt: Date.now() });
    return { marker: "KNOWLEDGE_CONNECTOR_DISABLED" as const };
  },
});
