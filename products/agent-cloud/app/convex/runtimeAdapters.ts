import { v } from "convex/values";
import { internalMutation, mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";
import { assertText, receiptFingerprint } from "./domain";

export const runtimeEngine = v.union(v.literal("mastra"), v.literal("langgraph"), v.literal("openai-agents"), v.literal("microsoft-agent-framework"), v.literal("google-adk"));

export function transportForEngine(engine: "mastra" | "langgraph" | "openai-agents" | "microsoft-agent-framework" | "google-adk") {
  return engine === "mastra" ? "mastra-native-v1" as const : "agent-oven-bridge-v1" as const;
}

function opaqueReference(value: string, field: string) {
  const clean = assertText(value, field, 240);
  if (!/^(?:env|vault):[A-Za-z0-9_./-]+$/.test(clean)) throw new Error("E_RUNTIME_ADAPTER_REFERENCE_FORBIDDEN");
  return clean;
}

/** Stores one engine configuration using references only; reachability remains worker-validated. */
export const configure = mutation({
  args: {
    agentSpecId: v.id("agentSpecs"), engine: runtimeEngine, label: v.string(), endpointRef: v.string(), secretRef: v.optional(v.string()),
    targetId: v.string(), environment: v.union(v.literal("sandbox"), v.literal("production")),
  },
  handler: async (ctx, args) => {
    const agent = await ctx.db.get(args.agentSpecId);
    if (!agent) throw new Error("E_AGENT_NOT_FOUND");
    await requireWorkspaceRole(ctx, agent.workspaceId, "admin");
    const endpointRef = opaqueReference(args.endpointRef, "runtime_endpoint_ref");
    const secretRef = args.secretRef ? opaqueReference(args.secretRef, "runtime_secret_ref") : undefined;
    const label = assertText(args.label, "runtime_label", 100);
    const targetId = assertText(args.targetId, "runtime_target_id", 160);
    const transport = transportForEngine(args.engine);
    const canonical = JSON.stringify({ endpointRef, engine: args.engine, environment: args.environment, secretRef: secretRef ?? null, targetId, transport });
    const configDigest = receiptFingerprint([canonical]);
    const existing = await ctx.db.query("runtimeAdapters").withIndex("by_agent_engine", (q) => q.eq("agentSpecId", agent._id).eq("engine", args.engine)).unique();
    const record = { workspaceId: agent.workspaceId, agentSpecId: agent._id, engine: args.engine, label, endpointRef, secretRef, targetId, environment: args.environment, transport, status: "setup-required" as const, configDigest, validationDigest: undefined, lastValidatedAt: undefined, updatedAt: Date.now() };
    const runtimeAdapterId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("runtimeAdapters", record);
    return { marker: "RUNTIME_ADAPTER_CONFIGURED" as const, runtimeAdapterId, engine: args.engine, transport, configDigest, status: "setup-required" as const };
  },
});

/** Lists configured engine adapters without resolving endpoint or credential references. */
export const list = query({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const agent = await ctx.db.get(args.agentSpecId);
    if (!agent) throw new Error("E_AGENT_NOT_FOUND");
    await requireWorkspaceRole(ctx, agent.workspaceId, "viewer");
    return ctx.db.query("runtimeAdapters").withIndex("by_agent", (q) => q.eq("agentSpecId", agent._id)).collect();
  },
});

/** Disables future dispatch through one adapter without rewriting pinned jobs. */
export const disable = mutation({
  args: { runtimeAdapterId: v.id("runtimeAdapters") },
  handler: async (ctx, args) => {
    const adapter = await ctx.db.get(args.runtimeAdapterId);
    if (!adapter) throw new Error("E_RUNTIME_ADAPTER_NOT_FOUND");
    await requireWorkspaceRole(ctx, adapter.workspaceId, "admin");
    await ctx.db.patch(adapter._id, { status: "disabled", updatedAt: Date.now() });
    return { marker: "RUNTIME_ADAPTER_DISABLED" as const, runtimeAdapterId: adapter._id };
  },
});

/** Records a trusted worker's reachability proof for the exact current configuration digest. */
export const recordValidation = internalMutation({
  args: { runtimeAdapterId: v.id("runtimeAdapters"), expectedConfigDigest: v.string(), validationDigest: v.string() },
  handler: async (ctx, args) => {
    const adapter = await ctx.db.get(args.runtimeAdapterId);
    if (!adapter) throw new Error("E_RUNTIME_ADAPTER_NOT_FOUND");
    if (adapter.configDigest !== args.expectedConfigDigest) throw new Error("E_RUNTIME_ADAPTER_DIGEST_MISMATCH");
    const now = Date.now();
    const validationDigest = assertText(args.validationDigest, "runtime_validation_digest", 120);
    await ctx.db.patch(adapter._id, { status: "ready", validationDigest, lastValidatedAt: now, updatedAt: now });
    return { marker: "RUNTIME_ADAPTER_VALIDATED" as const, runtimeAdapterId: adapter._id, validationDigest, lastValidatedAt: now };
  },
});
