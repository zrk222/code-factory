import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";
import { compileAgentIntent, runtimeCompatibility } from "./agentComposerDomain";
import { receiptFingerprint } from "./domain";

const runtimePreference = v.union(v.literal("auto"), v.literal("agent-oven-native"), v.literal("langgraph"), v.literal("mastra"));
const inferenceAccess = v.union(v.literal("agent-oven-api"), v.literal("byok"));

/** Compiles plain-language intent without executing a model or storing the raw brief. */
export const compile = mutation({
  args: { agentSpecId: v.id("agentSpecs"), description: v.string(), runtimePreference, inferenceAccess },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    const authorized = await requireWorkspaceRole(ctx, spec.workspaceId, "operator");
    const now = Date.now();
    const compiled = compileAgentIntent({ description: args.description, runtimePreference: args.runtimePreference, inferenceAccess: args.inferenceAccess });
    const draftId = await ctx.db.insert("agentCompositionDrafts", {
      workspaceId: spec.workspaceId,
      agentSpecId: spec._id,
      title: compiled.title,
      intentDigest: compiled.intentDigest,
      compilerDigest: compiled.compilerDigest,
      selectedRuntime: compiled.selectedRuntime,
      runtimeRationale: compiled.runtimeRationale,
      inferenceAccess: compiled.inferenceAccess,
      authorityPolicy: compiled.authorityPolicy,
      memoryPolicy: compiled.memoryPolicy,
      steps: compiled.steps,
      evidenceChecks: compiled.evidenceChecks,
      clarificationQuestions: compiled.clarificationQuestions,
      status: compiled.readiness === "ready-for-draft" ? "ready" : "needs-clarification",
      createdBy: authorized.tokenIdentifier,
      createdAt: now,
    });
    const previous = await ctx.db.query("receipts").withIndex("by_workspace_created", (q) => q.eq("workspaceId", spec.workspaceId)).order("desc").first();
    const fingerprint = receiptFingerprint([String(draftId), compiled.compilerDigest, "agent.composer.compiled", String(now)]);
    await ctx.db.insert("receipts", { workspaceId: spec.workspaceId, agentSpecId: spec._id, type: "agent-blueprint", event: "agent.composer.compiled", fingerprint, previousFingerprint: previous?.fingerprint, signatureState: "unsigned", createdAt: now });
    return { ...compiled, draftId, fingerprint, rawDescriptionStored: false as const };
  },
});

export const latest = query({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "viewer");
    const drafts = await ctx.db.query("agentCompositionDrafts").withIndex("by_agent_created", (q) => q.eq("agentSpecId", spec._id)).order("desc").take(10);
    return { marker: "AGENT_COMPOSER_READY" as const, compatibility: runtimeCompatibility, drafts };
  },
});

export const markApplied = mutation({
  args: { draftId: v.id("agentCompositionDrafts"), blueprintId: v.id("agentBlueprints"), expectedCompilerDigest: v.string() },
  handler: async (ctx, args) => {
    const draft = await ctx.db.get(args.draftId);
    if (!draft) throw new Error("E_AGENT_COMPOSER_DRAFT_NOT_FOUND");
    await requireWorkspaceRole(ctx, draft.workspaceId, "admin");
    if (draft.compilerDigest !== args.expectedCompilerDigest) throw new Error("E_AGENT_COMPOSER_DIGEST_MISMATCH");
    const blueprint = await ctx.db.get(args.blueprintId);
    if (!blueprint || blueprint.workspaceId !== draft.workspaceId || blueprint.agentSpecId !== draft.agentSpecId) throw new Error("E_AGENT_COMPOSER_BLUEPRINT_MISMATCH");
    await ctx.db.patch(draft._id, { status: "applied", appliedBlueprintId: blueprint._id, appliedAt: Date.now() });
    return { marker: "AGENT_COMPOSER_APPLIED" as const, draftId: draft._id, blueprintId: blueprint._id };
  },
});
