import { v } from "convex/values";
import type { Doc } from "./_generated/dataModel";
import type { MutationCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import {
  type AgentSpecSemantic,
  assertText,
  canonicalAgentSpec,
  parseAgentSpecImport,
  receiptFingerprint,
  validateSecretReference,
} from "./domain";
import { requireWorkspaceRole } from "./access";

function semanticFromSpec(spec: Doc<"agentSpecs"> | Doc<"agentSpecVersions">): AgentSpecSemantic {
  return {
    name: spec.name,
    repository: spec.repository,
    providerProfile: spec.providerProfile,
    memoryMode: spec.memoryMode,
    authorityMode: spec.authorityMode,
    hardBudgetCents: spec.hardBudgetCents,
    validators: spec.validators,
  };
}

async function appendVersion(
  ctx: MutationCtx,
  spec: Doc<"agentSpecs">,
  semantic: AgentSpecSemantic,
  source: "import" | "rollback",
  restoredFromVersion?: number,
) {
  const version = spec.version + 1;
  const now = Date.now();
  const canonical = canonicalAgentSpec(semantic);
  const digest = receiptFingerprint([canonical]);
  await ctx.db.patch(spec._id, { ...semantic, version, updatedAt: now });
  await ctx.db.insert("agentSpecVersions", {
    workspaceId: spec.workspaceId,
    agentSpecId: spec._id,
    version,
    ...semantic,
    digest,
    source,
    restoredFromVersion,
    createdAt: now,
  });
  return { version, digest, now };
}

export const exportAgentSpec = query({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "viewer");
    const canonical = canonicalAgentSpec(semanticFromSpec(spec));
    return {
      marker: "AGENT_SPEC_EXPORTED" as const,
      canonical,
      digest: receiptFingerprint([canonical]),
      version: spec.version,
    };
  },
});

export const importAgentSpec = mutation({
  args: { agentSpecId: v.id("agentSpecs"), canonical: v.string(), digest: v.string() },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "admin");
    const semantic = parseAgentSpecImport(args.canonical);
    const normalized = canonicalAgentSpec(semantic);
    const digest = receiptFingerprint([normalized]);
    if (args.digest !== digest) throw new Error("E_IMPORT_DIGEST_MISMATCH");
    const result = await appendVersion(ctx, spec, semantic, "import");
    await ctx.db.insert("auditEvents", {
      workspaceId: spec.workspaceId,
      actor: "builder@factory.local",
      event: "agent-spec.imported",
      targetType: "agentSpec",
      targetId: String(spec._id),
      detail: `Canonical AgentSpec imported as version ${result.version}.`,
      createdAt: result.now,
    });
    return {
      marker: "AGENT_SPEC_IMPORTED" as const,
      digestMarker: "IMPORT_DIGEST_MATCHED" as const,
      historyMarker: "VERSION_HISTORY_APPEND_ONLY" as const,
      version: result.version,
      digest: result.digest,
    };
  },
});

export const rollbackAgentSpec = mutation({
  args: { agentSpecId: v.id("agentSpecs"), targetVersion: v.number() },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "admin");
    const historical = await ctx.db
      .query("agentSpecVersions")
      .withIndex("by_agent_version", (q) => q.eq("agentSpecId", spec._id).eq("version", args.targetVersion))
      .unique();
    if (!historical) throw new Error("E_VERSION_NOT_FOUND");
    const result = await appendVersion(ctx, spec, semanticFromSpec(historical), "rollback", historical.version);
    await ctx.db.insert("auditEvents", {
      workspaceId: spec.workspaceId,
      actor: "operator@factory.local",
      event: "agent-spec.rolled-back",
      targetType: "agentSpec",
      targetId: String(spec._id),
      detail: `Version ${historical.version} restored as new head version ${result.version}.`,
      createdAt: result.now,
    });
    return {
      marker: "AGENT_SPEC_ROLLED_BACK" as const,
      versionMarker: "ROLLBACK_VERSION_FOUND" as const,
      historyMarker: "VERSION_HISTORY_APPEND_ONLY" as const,
      restoredFromVersion: historical.version,
      version: result.version,
    };
  },
});

export const setLifecycle = mutation({
  args: {
    agentSpecId: v.id("agentSpecs"),
    action: v.union(v.literal("pause"), v.literal("resume"), v.literal("revoke")),
    reason: v.string(),
  },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    const authorized = await requireWorkspaceRole(ctx, spec.workspaceId, "admin");
    const reason = assertText(args.reason, "lifecycle_reason", 500);
    if (spec.status === "revoked" && args.action === "resume") throw new Error("E_AGENT_REVOKED");
    if (spec.status === "revoked") throw new Error("E_AGENT_REVOKED");
    if (args.action === "resume" && spec.status !== "suspended") throw new Error("E_INVALID_LIFECYCLE_TRANSITION");
    if (args.action === "pause" && spec.status !== "active") throw new Error("E_INVALID_LIFECYCLE_TRANSITION");

    const nextStatus = args.action === "resume" ? "active" : args.action === "pause" ? "suspended" : "revoked";
    const now = Date.now();
    let closedRuns = 0;
    let closedApprovals = 0;
    if (args.action !== "resume") {
      const runs = await ctx.db
        .query("runs")
        .withIndex("by_agent_started", (q) => q.eq("agentSpecId", spec._id))
        .collect();
      for (const run of runs.filter((item) => item.status === "awaiting-approval")) {
        await ctx.db.patch(run._id, { status: "blocked", completedAt: now });
        closedRuns += 1;
        const approval = await ctx.db.query("approvals").withIndex("by_run", (q) => q.eq("runId", run._id)).unique();
        if (approval?.status === "pending") {
          await ctx.db.patch(approval._id, {
            status: "rejected",
            decidedBy: authorized.tokenIdentifier,
            decidedAt: now,
            rationale: `Lifecycle ${args.action}: ${reason}`,
          });
          closedApprovals += 1;
        }
      }
    }
    await ctx.db.patch(spec._id, { status: nextStatus, updatedAt: now });
    const previous = await ctx.db
      .query("receipts")
      .withIndex("by_workspace_created", (q) => q.eq("workspaceId", spec.workspaceId))
      .order("desc")
      .first();
    const fingerprint = receiptFingerprint([String(spec._id), args.action, reason, String(now)]);
    await ctx.db.insert("receipts", {
      workspaceId: spec.workspaceId,
      agentSpecId: spec._id,
      type: "agent-lifecycle",
      event: `agent.${args.action}`,
      fingerprint,
      previousFingerprint: previous?.fingerprint,
      signatureState: "unsigned",
      createdAt: now,
    });
    await ctx.db.insert("auditEvents", {
      workspaceId: spec.workspaceId,
      actor: authorized.tokenIdentifier,
      event: `agent.${args.action}`,
      targetType: "agentSpec",
      targetId: String(spec._id),
      detail: `${reason} Closed ${closedRuns} run(s) and ${closedApprovals} approval(s).`,
      createdAt: now,
    });
    const marker = args.action === "pause"
      ? "AGENT_EMERGENCY_STOPPED"
      : args.action === "resume"
        ? "AGENT_RESUMED"
        : "AGENT_PERMANENTLY_REVOKED";
    return { marker, actionMarker: "LIFECYCLE_ACTION_ALLOWED" as const, status: nextStatus, closedRuns, closedApprovals, fingerprint };
  },
});

export const configureProvider = mutation({
  args: {
    workspaceId: v.id("workspaces"),
    provider: v.union(v.literal("openai"), v.literal("anthropic")),
    label: v.string(),
    secretRef: v.string(),
    enabled: v.boolean(),
  },
  handler: async (ctx, args) => {
    const workspace = await ctx.db.get(args.workspaceId);
    if (!workspace) throw new Error("E_WORKSPACE_NOT_FOUND");
    await requireWorkspaceRole(ctx, workspace._id, "admin");
    const label = assertText(args.label, "provider_label", 80);
    const secretRef = validateSecretReference(args.secretRef);
    const existing = await ctx.db
      .query("providerConnections")
      .withIndex("by_workspace_provider", (q) => q.eq("workspaceId", workspace._id).eq("provider", args.provider))
      .unique();
    const record = {
      workspaceId: workspace._id,
      provider: args.provider,
      label,
      secretRef,
      status: args.enabled ? "enabled" as const : "disabled" as const,
      updatedAt: Date.now(),
    };
    const connectionId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("providerConnections", record);
    await ctx.db.insert("auditEvents", {
      workspaceId: workspace._id,
      actor: "builder@factory.local",
      event: "provider-reference.configured",
      targetType: "providerConnection",
      targetId: String(connectionId),
      detail: `${args.provider} reference ${label} configured as ${record.status}; no secret value stored.`,
      createdAt: record.updatedAt,
    });
    return {
      marker: "BYOK_REFERENCE_BOUND" as const,
      rawSecretMarker: "RAW_SECRET_ABSENT" as const,
      schemeMarker: "SECRET_SCHEME_ALLOWED" as const,
      secretValuesMarker: "SECRET_VALUES_ABSENT" as const,
      connectionId,
      provider: args.provider,
      secretRef,
      status: record.status,
    };
  },
});
