import { mutation } from "./_generated/server";
import type { Id } from "./_generated/dataModel";
import type { MutationCtx } from "./_generated/server";
import { canonicalAgentSpec, DEMO_WORKSPACE_SLUG, receiptFingerprint } from "./domain";
import { appendIdentityEvidence, principal, requireWorkspaceRole } from "./access";
import { ensureCreditAccount } from "./credits";

async function ensureWorkspaceOwner(ctx: MutationCtx, workspaceId: Id<"workspaces">, tokenIdentifier: string) {
  const existing = await ctx.db.query("workspaceMemberships").withIndex("by_workspace_subject", (q) => q.eq("workspaceId", workspaceId).eq("tokenIdentifier", tokenIdentifier)).unique();
  if (existing?.status === "active") return existing._id;
  const memberships = await ctx.db.query("workspaceMemberships").withIndex("by_workspace_status", (q) => q.eq("workspaceId", workspaceId)).collect();
  if (memberships.length !== 0) throw new Error("E_WORKSPACE_ACCESS_DENIED");
  const now = Date.now();
  const membershipId = await ctx.db.insert("workspaceMemberships", { workspaceId, tokenIdentifier, memberLabel: "Workspace owner", role: "owner", status: "active", createdBy: "authenticated-seed-bootstrap", createdAt: now });
  await appendIdentityEvidence(ctx, workspaceId, membershipId, "identity.owner-bootstrapped", "owner", now);
  return membershipId;
}

export const ensureDemo = mutation({
  args: {},
  handler: async (ctx) => {
    const derived = await principal(ctx);
    const activeMemberships = await ctx.db
      .query("workspaceMemberships")
      .withIndex("by_subject_status", (q) => q.eq("tokenIdentifier", derived.tokenIdentifier).eq("status", "active"))
      .collect();
    const existing = activeMemberships[0] ? await ctx.db.get(activeMemberships[0].workspaceId) : null;

    if (existing) {
      await requireWorkspaceRole(ctx, existing._id, "viewer");
      await ensureCreditAccount(ctx, existing._id);
      const specs = await ctx.db
        .query("agentSpecs")
        .withIndex("by_workspace", (q) => q.eq("workspaceId", existing._id))
        .collect();
      const current = specs[0];
      if (current) {
        const initialVersion = await ctx.db
          .query("agentSpecVersions")
          .withIndex("by_agent_version", (q) => q.eq("agentSpecId", current._id).eq("version", current.version))
          .unique();
        if (!initialVersion) {
          const semantic = {
            name: current.name,
            repository: current.repository,
            providerProfile: current.providerProfile,
            memoryMode: current.memoryMode,
            authorityMode: current.authorityMode,
            hardBudgetCents: current.hardBudgetCents,
            validators: current.validators,
          };
          await ctx.db.insert("agentSpecVersions", {
            workspaceId: existing._id,
            agentSpecId: current._id,
            version: current.version,
            ...semantic,
            digest: receiptFingerprint([canonicalAgentSpec(semantic)]),
            source: "seed",
            createdAt: current.updatedAt,
          });
        }
      }
      const memories = await ctx.db
        .query("memories")
        .withIndex("by_workspace_deleted", (q) => q.eq("workspaceId", existing._id))
        .collect();
      for (const memory of memories) {
        if (memory.policyVersion === undefined || memory.safetyState === undefined) await ctx.db.patch(memory._id, {
          policyVersion: "memory-policy.v1",
          safetyState: memory.safetyState ?? "eligible",
          safetyReason: memory.safetyReason ?? "legacy-record-reviewed",
        });
      }
      return { marker: "DEMO_SEED_IDEMPOTENT" as const, workspaceId: existing._id, agentSpecId: specs[0]?._id };
    }

    const now = Date.now();
    const workspaceSlug = `${DEMO_WORKSPACE_SLUG}-${receiptFingerprint([derived.tokenIdentifier]).slice(0, 16)}`;
    const conflictingWorkspace = await ctx.db.query("workspaces").withIndex("by_slug", (q) => q.eq("slug", workspaceSlug)).unique();
    if (conflictingWorkspace) throw new Error("E_WORKSPACE_BOOTSTRAP_CONFLICT");
    const workspaceId = await ctx.db.insert("workspaces", {
      slug: workspaceSlug,
      name: "My Agent Oven Workspace",
      plan: "pilot",
      createdAt: now,
    });
    const agentSpecId = await ctx.db.insert("agentSpecs", {
      workspaceId,
      name: "PR Assurance",
      repository: "zrk222/code-factory",
      providerProfile: "balanced",
      memoryMode: "architecture-history",
      authorityMode: "approval-required",
      hardBudgetCents: 450,
      validators: ["Requirements coverage", "Test suite", "Trust policy", "Receipt integrity"],
      version: 1,
      status: "active",
      updatedAt: now,
    });
    const initialSemantic = {
      name: "PR Assurance",
      repository: "zrk222/code-factory",
      providerProfile: "balanced" as const,
      memoryMode: "architecture-history" as const,
      authorityMode: "approval-required" as const,
      hardBudgetCents: 450,
      validators: ["Requirements coverage", "Test suite", "Trust policy", "Receipt integrity"],
    };
    const initialCanonical = canonicalAgentSpec(initialSemantic);
    await ctx.db.insert("agentSpecVersions", {
      workspaceId,
      agentSpecId,
      version: 1,
      ...initialSemantic,
      digest: receiptFingerprint([initialCanonical]),
      source: "seed",
      createdAt: now,
    });

    const routes = [
      ["economy", "OpenAI", "gpt-5-mini", "Anthropic", "claude-haiku"] as const,
      ["balanced", "OpenAI", "gpt-5", "Anthropic", "claude-sonnet"] as const,
      ["highest-quality", "Anthropic", "claude-opus", "OpenAI", "gpt-5-pro"] as const,
    ];
    for (const [profile, primaryProvider, primaryModel, fallbackProvider, fallbackModel] of routes) {
      await ctx.db.insert("providerRoutes", {
        workspaceId,
        profile,
        primaryProvider,
        primaryModel,
        fallbackProvider,
        fallbackModel,
        cacheAffinity: true,
        updatedAt: now,
      });
    }
    await ctx.db.insert("auditEvents", {
      workspaceId,
      actor: "system",
      event: "workspace.seeded",
      targetType: "workspace",
      targetId: String(workspaceId),
      detail: "Tenant-scoped workspace and starter AgentSpec created.",
      createdAt: now,
    });
    await ensureWorkspaceOwner(ctx, workspaceId, derived.tokenIdentifier);
    await ensureCreditAccount(ctx, workspaceId);
    return { marker: "DEMO_SEED_IDEMPOTENT" as const, workspaceId, agentSpecId };
  },
});
