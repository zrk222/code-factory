import { query } from "./_generated/server";
import { v } from "convex/values";
import { canonicalAgentSpec, canonicalMemoryExport, receiptFingerprint, toMemoryExportRecords } from "./domain";
import { requireWorkspaceRole } from "./access";
import { planCatalog } from "./credits";

export const overview = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    await requireWorkspaceRole(ctx, args.workspaceId, "viewer");
    const workspace = await ctx.db.get(args.workspaceId);
    if (!workspace) return null;

    const [agentSpecs, runs, approvals, receipts, memoryLedger, routes, providerConnections, knowledgeConnectors, auditEvents, releases, incidents] = await Promise.all([
      ctx.db.query("agentSpecs").withIndex("by_workspace", (q) => q.eq("workspaceId", workspace._id)).collect(),
      ctx.db.query("runs").withIndex("by_workspace_started", (q) => q.eq("workspaceId", workspace._id)).order("desc").take(20),
      ctx.db.query("approvals").withIndex("by_workspace_status", (q) => q.eq("workspaceId", workspace._id)).collect(),
      ctx.db.query("receipts").withIndex("by_workspace_created", (q) => q.eq("workspaceId", workspace._id)).order("desc").take(30),
      ctx.db.query("memories").withIndex("by_workspace_deleted", (q) => q.eq("workspaceId", workspace._id)).collect(),
      ctx.db.query("providerRoutes").withIndex("by_workspace_profile", (q) => q.eq("workspaceId", workspace._id)).collect(),
      ctx.db.query("providerConnections").withIndex("by_workspace_provider", (q) => q.eq("workspaceId", workspace._id)).collect(),
      ctx.db.query("knowledgeConnectors").withIndex("by_workspace_status", (q) => q.eq("workspaceId", workspace._id)).collect(),
      ctx.db.query("auditEvents").withIndex("by_workspace_created", (q) => q.eq("workspaceId", workspace._id)).order("desc").take(20),
      ctx.db.query("releaseCandidates").withIndex("by_workspace_created", (q) => q.eq("workspaceId", workspace._id)).order("desc").take(20),
      ctx.db.query("incidents").withIndex("by_workspace_opened", (q) => q.eq("workspaceId", workspace._id)).order("desc").take(20),
    ]);

    const agentSpec = agentSpecs[0] ?? null;
    const blueprint = agentSpec ? await ctx.db.query("agentBlueprints").withIndex("by_agent", (q) => q.eq("agentSpecId", agentSpec._id)).unique() : null;
    const blueprintVersions = blueprint ? await ctx.db.query("agentBlueprintVersions").withIndex("by_blueprint_version", (q) => q.eq("blueprintId", blueprint._id)).collect() : [];
    const creditAccount = await ctx.db.query("creditAccounts").withIndex("by_workspace", (q) => q.eq("workspaceId", workspace._id)).unique();
    const creditTransactions = await ctx.db.query("creditTransactions").withIndex("by_workspace_created", (q) => q.eq("workspaceId", workspace._id)).order("desc").take(20);
    const inferenceBinding = agentSpec ? await ctx.db.query("inferenceBindings").withIndex("by_agent", (q) => q.eq("agentSpecId", agentSpec._id)).unique() : null;
    const runtimeAdapters = agentSpec ? await ctx.db.query("runtimeAdapters").withIndex("by_agent", (q) => q.eq("agentSpecId", agentSpec._id)).collect() : [];
    const executionJobs = await ctx.db.query("executionJobs").withIndex("by_workspace_created", (q) => q.eq("workspaceId", workspace._id)).order("desc").take(20);
    const backupSnapshots = await ctx.db.query("backupSnapshots").withIndex("by_workspace_requested", (q) => q.eq("workspaceId", workspace._id)).order("desc").take(10);
    const restoreDrills = await ctx.db.query("restoreDrills").withIndex("by_workspace_requested", (q) => q.eq("workspaceId", workspace._id)).order("desc").take(10);
    const memories = memoryLedger.filter((memory) => memory.deletedAt === undefined && memory.supersededAt === undefined && memory.safetyState !== "quarantined");
    const memoryRecords = toMemoryExportRecords(memoryLedger.map((memory) => ({
      key: String(memory._id),
      supersedesKey: memory.supersedesMemoryId ? String(memory.supersedesMemoryId) : undefined,
      subject: memory.subject,
      content: memory.content,
      source: memory.source,
      purpose: memory.purpose,
      provenance: memory.provenance,
      confidence: memory.confidence,
      retentionDays: memory.retentionDays,
      createdAt: memory.createdAt,
      deletedAt: memory.deletedAt,
      supersededAt: memory.supersededAt,
    })));
    const memoryCanonical = canonicalMemoryExport(memoryRecords);
    const memoryExport = {
      marker: "MEMORY_EXPORT_READY" as const,
      sanitizedMarker: "MEMORY_EXPORT_SANITIZED" as const,
      canonical: memoryCanonical,
      digest: receiptFingerprint([memoryCanonical]),
      records: memoryRecords,
    };
    const versions = agentSpec
      ? await ctx.db.query("agentSpecVersions").withIndex("by_agent_version", (q) => q.eq("agentSpecId", agentSpec._id)).order("desc").take(30)
      : [];
    const agentSpecExport = agentSpec ? (() => {
      const canonical = canonicalAgentSpec({
        name: agentSpec.name,
        repository: agentSpec.repository,
        providerProfile: agentSpec.providerProfile,
        memoryMode: agentSpec.memoryMode,
        authorityMode: agentSpec.authorityMode,
        hardBudgetCents: agentSpec.hardBudgetCents,
        validators: agentSpec.validators,
      });
      return { marker: "AGENT_SPEC_EXPORTED" as const, canonical, digest: receiptFingerprint([canonical]), version: agentSpec.version };
    })() : null;

    const runDetails = await Promise.all(
      runs.map(async (run) => {
        const approval = await ctx.db.query("approvals").withIndex("by_run", (q) => q.eq("runId", run._id)).unique();
        return {
          ...run,
          gates: await ctx.db.query("gates").withIndex("by_run_order", (q) => q.eq("runId", run._id)).collect(),
          approval,
          adversarialReview: approval ? await ctx.db.query("adversarialApprovalReviews").withIndex("by_approval", (q) => q.eq("approvalId", approval._id)).unique() : null,
        };
      }),
    );
    const incidentDetails = await Promise.all(incidents.map(async (incident) => ({
      ...incident,
      checks: await ctx.db.query("incidentChecks").withIndex("by_incident_check", (q) => q.eq("incidentId", incident._id)).collect(),
    })));

    return {
      marker: "PRODUCT_VIEWS_BOUND" as const,
      workspace,
      agentSpec,
      blueprint,
      blueprintVersions,
      creditAccount,
      creditTransactions,
      creditPlans: planCatalog,
      inferenceBinding,
      runtimeAdapters,
      executionJobs,
      backupSnapshots,
      restoreDrills,
      versions,
      agentSpecExport,
      runs: runDetails,
      approvals,
      receipts,
      memories,
      memoryLedger,
      memoryExport,
      routes,
      providerConnections,
      knowledgeConnectors,
      auditEvents,
      releases,
      incidents: incidentDetails,
    };
  },
});
