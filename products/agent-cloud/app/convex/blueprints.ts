import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";
import { assertIntegerRange, assertText, receiptFingerprint } from "./domain";
import { quoteBlueprintCredits } from "./pricing";

const mode = v.union(v.literal("guided"), v.literal("architect"));
const triggerKind = v.union(v.literal("manual"), v.literal("schedule"), v.literal("webhook"), v.literal("event"));
const stepKind = v.union(v.literal("retrieve"), v.literal("reason"), v.literal("act"), v.literal("validate"), v.literal("notify"));
const memoryPolicy = v.union(v.literal("none"), v.literal("run-only"), v.literal("governed"));
const modelPolicy = v.union(v.literal("economy"), v.literal("balanced"), v.literal("highest-quality"), v.literal("auto"));
const authorityPolicy = v.union(v.literal("read-only"), v.literal("propose"), v.literal("approval-required"));
const evidenceLevel = v.union(v.literal("essential"), v.literal("full"));
const runtimeEngine = v.union(v.literal("agent-oven-native"), v.literal("langgraph"), v.literal("mastra"));
const inferenceAccess = v.union(v.literal("agent-oven-api"), v.literal("byok"));
const flow = v.union(v.literal("sequential"), v.literal("parallel"), v.literal("branch"), v.literal("loop"));
const step = v.object({ id: v.string(), label: v.string(), kind: stepKind, connectorProvider: v.optional(v.string()), humanGate: v.boolean(), flow: v.optional(flow), dependsOn: v.optional(v.array(v.string())), conditionRef: v.optional(v.string()), maxIterations: v.optional(v.number()) });

/** Saves an editable blueprint head and appends an immutable canonical version. */
export const save = mutation({
  args: { agentSpecId: v.id("agentSpecs"), templateId: v.string(), name: v.string(), mode, triggerKind, triggerLabel: v.string(), steps: v.array(step), memoryPolicy, modelPolicy, authorityPolicy, evidenceLevel, hardBudgetCents: v.number(), runtimeEngine: v.optional(runtimeEngine), inferenceAccess: v.optional(inferenceAccess) },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "admin");
    if (args.steps.length < 1 || args.steps.length > 20) throw new Error("E_BLUEPRINT_STEP_COUNT");
    const normalizedSteps = args.steps.map((item) => {
      const maxIterations = item.flow === "loop" ? item.maxIterations ?? 3 : undefined;
      if (maxIterations !== undefined) assertIntegerRange(maxIterations, "max_iterations", 1, 20);
      return { id: assertText(item.id, "step_id", 80), label: assertText(item.label, "step_label", 160), kind: item.kind, connectorProvider: item.connectorProvider ? assertText(item.connectorProvider, "connector_provider", 80) : undefined, humanGate: item.humanGate, flow: item.flow ?? "sequential" as const, dependsOn: item.dependsOn?.map((dependency) => assertText(dependency, "step_dependency", 80)), conditionRef: item.conditionRef ? assertText(item.conditionRef, "condition_ref", 120) : undefined, maxIterations };
    });
    if (new Set(normalizedSteps.map((item) => item.id)).size !== normalizedSteps.length) throw new Error("E_BLUEPRINT_STEP_ID_DUPLICATE");
    const stepIds = new Set(normalizedSteps.map((item) => item.id));
    if (normalizedSteps.some((item) => item.dependsOn?.some((dependency) => !stepIds.has(dependency) || dependency === item.id))) throw new Error("E_BLUEPRINT_DEPENDENCY_INVALID");
    assertIntegerRange(args.hardBudgetCents, "hard_budget", 1, 100000000);
    const semantic = { templateId: assertText(args.templateId, "template_id", 120), name: assertText(args.name, "blueprint_name", 120), mode: args.mode, triggerKind: args.triggerKind, triggerLabel: assertText(args.triggerLabel, "trigger_label", 160), steps: normalizedSteps, memoryPolicy: args.memoryPolicy, modelPolicy: args.modelPolicy, authorityPolicy: args.authorityPolicy, evidenceLevel: args.evidenceLevel, hardBudgetCents: args.hardBudgetCents, runtimeEngine: args.runtimeEngine ?? "agent-oven-native" as const, inferenceAccess: args.inferenceAccess ?? "byok" as const };
    const credits = quoteBlueprintCredits(semantic).total;
    const canonical = JSON.stringify(semantic);
    const existing = await ctx.db.query("agentBlueprints").withIndex("by_agent", (q) => q.eq("agentSpecId", spec._id)).unique();
    const now = Date.now();
    const version = (existing?.version ?? 0) + 1;
    const record = { workspaceId: spec.workspaceId, agentSpecId: spec._id, ...semantic, estimatedPlatformCredits: credits, version, status: "draft" as const, updatedAt: now };
    const blueprintId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("agentBlueprints", record);
    const digest = receiptFingerprint([canonical]);
    await ctx.db.insert("agentBlueprintVersions", { workspaceId: spec.workspaceId, agentSpecId: spec._id, blueprintId, version, canonical, digest, estimatedPlatformCredits: credits, runtimeEngine: semantic.runtimeEngine, inferenceAccess: semantic.inferenceAccess, createdAt: now });
    return { marker: "AGENT_BLUEPRINT_SAVED" as const, blueprintId, version, digest, estimatedPlatformCredits: credits, status: "draft" as const };
  },
});

/** Returns a deterministic dry-run plan with connector and approval readiness findings. */
export const simulate = query({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "viewer");
    const blueprint = await ctx.db.query("agentBlueprints").withIndex("by_agent", (q) => q.eq("agentSpecId", spec._id)).unique();
    if (!blueprint) return null;
    const connectors = await ctx.db.query("knowledgeConnectors").withIndex("by_workspace_status", (q) => q.eq("workspaceId", spec.workspaceId)).collect();
    const blockers = blueprint.steps.flatMap((item) => item.connectorProvider && !connectors.some((connector) => connector.provider === item.connectorProvider && connector.status === "ready") ? [`Connector ${item.connectorProvider} is not authorized.`] : []);
    const runtimeBlocker = blueprint.runtimeEngine && blueprint.runtimeEngine !== "agent-oven-native"
      ? (await ctx.db.query("runtimeAdapters").withIndex("by_agent_engine", (q) => q.eq("agentSpecId", spec._id).eq("engine", blueprint.runtimeEngine as "langgraph" | "mastra")).unique())?.status !== "ready"
        ? [`${blueprint.runtimeEngine} runtime adapter is not validated.`]
        : []
      : [];
    const allBlockers = [...blockers, ...runtimeBlocker];
    return { marker: "AGENT_BLUEPRINT_SIMULATED" as const, blueprintId: blueprint._id, version: blueprint.version, runtimeEngine: blueprint.runtimeEngine ?? "agent-oven-native", inferenceAccess: blueprint.inferenceAccess ?? "byok", stages: blueprint.steps.map((item, index) => ({ order: index + 1, label: item.label, kind: item.kind, flow: item.flow ?? "sequential", dependsOn: item.dependsOn ?? [], maxIterations: item.maxIterations, humanGate: item.humanGate })), estimatedPlatformCredits: blueprint.estimatedPlatformCredits, maxInferenceCostCents: blueprint.hardBudgetCents, approvalRequired: blueprint.authorityPolicy === "approval-required" || blueprint.steps.some((item) => item.humanGate), blockers: allBlockers, ready: allBlockers.length === 0 };
  },
});

/** Activates only a simulated-ready draft and writes append-only activation evidence. */
export const activate = mutation({
  args: { blueprintId: v.id("agentBlueprints"), creditReservationId: v.id("creditReservations") },
  handler: async (ctx, args) => {
    const blueprint = await ctx.db.get(args.blueprintId);
    if (!blueprint) throw new Error("E_BLUEPRINT_NOT_FOUND");
    await requireWorkspaceRole(ctx, blueprint.workspaceId, "admin");
    const creditReservation = await ctx.db.get(args.creditReservationId);
    if (!creditReservation || creditReservation.blueprintId !== blueprint._id || creditReservation.workspaceId !== blueprint.workspaceId || creditReservation.state !== "settled") throw new Error("E_BLUEPRINT_CREDITS_NOT_SETTLED");
    const connectors = await ctx.db.query("knowledgeConnectors").withIndex("by_workspace_status", (q) => q.eq("workspaceId", blueprint.workspaceId)).collect();
    if (blueprint.steps.some((item) => item.connectorProvider && !connectors.some((connector) => connector.provider === item.connectorProvider && connector.status === "ready"))) throw new Error("E_BLUEPRINT_CONNECTOR_NOT_READY");
    if (blueprint.runtimeEngine && blueprint.runtimeEngine !== "agent-oven-native") {
      const adapter = await ctx.db.query("runtimeAdapters").withIndex("by_agent_engine", (q) => q.eq("agentSpecId", blueprint.agentSpecId).eq("engine", blueprint.runtimeEngine as "langgraph" | "mastra")).unique();
      if (!adapter || adapter.status !== "ready") throw new Error("E_BLUEPRINT_RUNTIME_ADAPTER_NOT_READY");
    }
    const now = Date.now();
    await ctx.db.patch(blueprint._id, { status: "active", updatedAt: now });
    const previous = await ctx.db.query("receipts").withIndex("by_workspace_created", (q) => q.eq("workspaceId", blueprint.workspaceId)).order("desc").first();
    const fingerprint = receiptFingerprint([String(blueprint._id), String(blueprint.version), "blueprint.activated", String(now)]);
    await ctx.db.insert("receipts", { workspaceId: blueprint.workspaceId, agentSpecId: blueprint.agentSpecId, type: "agent-blueprint", event: "blueprint.activated", fingerprint, previousFingerprint: previous?.fingerprint, signatureState: "unsigned", createdAt: now });
    return { marker: "AGENT_BLUEPRINT_ACTIVATED" as const, blueprintId: blueprint._id, version: blueprint.version, fingerprint };
  },
});

/** Reads the current blueprint head and immutable version history. */
export const get = query({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "viewer");
    const blueprint = await ctx.db.query("agentBlueprints").withIndex("by_agent", (q) => q.eq("agentSpecId", spec._id)).unique();
    if (!blueprint) return null;
    const versions = await ctx.db.query("agentBlueprintVersions").withIndex("by_blueprint_version", (q) => q.eq("blueprintId", blueprint._id)).collect();
    return { blueprint, versions };
  },
});
