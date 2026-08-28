import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";

const mode = v.union(v.literal("inherit-workspace"), v.literal("dedicated"));
const providerProfile = v.union(v.literal("economy"), v.literal("balanced"), v.literal("highest-quality"));

/** Binds an agent to a reusable workspace provider reference or a dedicated connection. */
export const bind = mutation({
  args: { agentSpecId: v.id("agentSpecs"), mode, providerConnectionId: v.optional(v.id("providerConnections")), providerProfile },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "admin");
    if (args.mode === "dedicated" && !args.providerConnectionId) throw new Error("E_DEDICATED_CONNECTION_REQUIRED");
    const connection = args.providerConnectionId ? await ctx.db.get(args.providerConnectionId) : null;
    if (connection && connection.workspaceId !== spec.workspaceId) throw new Error("E_CROSS_TENANT_RESOURCE");
    const status = args.mode === "inherit-workspace" || connection?.status === "enabled" ? "ready" as const : "setup-required" as const;
    const record = { workspaceId: spec.workspaceId, agentSpecId: spec._id, mode: args.mode, providerConnectionId: args.providerConnectionId, providerProfile: args.providerProfile, status, updatedAt: Date.now() };
    const existing = await ctx.db.query("inferenceBindings").withIndex("by_agent", (q) => q.eq("agentSpecId", spec._id)).unique();
    const bindingId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("inferenceBindings", record);
    await ctx.db.insert("auditEvents", { workspaceId: spec.workspaceId, actor: "inference-router@factory.local", event: "inference-binding.updated", targetType: "inferenceBinding", targetId: String(bindingId), detail: `${args.mode} binding set to ${args.providerProfile}; raw provider credentials absent.`, createdAt: record.updatedAt });
    return { marker: "AGENT_INFERENCE_BOUND" as const, credentialMarker: "RAW_CREDENTIAL_ABSENT" as const, bindingId, status };
  },
});

/** Reads only the authorized agent's opaque inference binding metadata. */
export const get = query({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "viewer");
    return ctx.db.query("inferenceBindings").withIndex("by_agent", (q) => q.eq("agentSpecId", spec._id)).unique();
  },
});
