import { v } from "convex/values";
import { internalMutation, mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";
import { assertIntegerRange, assertText, receiptFingerprint } from "./domain";
import { assessSourceGroups } from "../runtime/sourceAssurance";
import { evaluateProductionReadiness } from "./productionReadinessDomain";

declare const process: { env: Record<string, string | undefined> };

function safeObjectRef(value: string) {
  const ref = assertText(value, "backup_object_ref", 500);
  if (!/^(?:s3|azure-blob|gcs):\/\//.test(ref)) throw new Error("E_BACKUP_OBJECT_REF_SCHEME");
  if (/\/\/[^/\s]+:[^/@\s]+@/i.test(ref) || /[?&](?:token|key|secret|password)=/i.test(ref)) throw new Error("E_BACKUP_CREDENTIAL_FORBIDDEN");
  return ref;
}

/** Explains production activation to administrators without exposing deployment configuration. */
export const productionReadiness = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    await requireWorkspaceRole(ctx, args.workspaceId, "admin");
    return evaluateProductionReadiness({
      AUTH0_DOMAIN: process.env.AUTH0_DOMAIN,
      AUTH0_CLIENT_ID: process.env.AUTH0_CLIENT_ID,
      AGENT_OVEN_APP_URL: process.env.AGENT_OVEN_APP_URL,
      AGENT_OVEN_BILLING_WEBHOOK_SECRET_REF: process.env.AGENT_OVEN_BILLING_WEBHOOK_SECRET_REF,
      AGENT_OVEN_EMAIL_CONNECTION_REF: process.env.AGENT_OVEN_EMAIL_CONNECTION_REF,
      AGENT_OVEN_RUNTIME_WORKER_SECRET_REF: process.env.AGENT_OVEN_RUNTIME_WORKER_SECRET_REF,
      AGENT_OVEN_BACKUP_STORAGE_REF: process.env.AGENT_OVEN_BACKUP_STORAGE_REF,
      AGENT_OVEN_SECURITY_CONTACT: process.env.AGENT_OVEN_SECURITY_CONTACT,
    });
  },
});

/** Computes authorized operational health from queue, backup, connector, and credit state. */
export const health = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    await requireWorkspaceRole(ctx, args.workspaceId, "viewer");
    const [jobs, connectors, authoritativeSources, backups, drills, account] = await Promise.all([
      ctx.db.query("executionJobs").withIndex("by_workspace_created", (q) => q.eq("workspaceId", args.workspaceId)).order("desc").take(100),
      ctx.db.query("knowledgeConnectors").withIndex("by_workspace_status", (q) => q.eq("workspaceId", args.workspaceId)).collect(),
      ctx.db.query("authoritativeSources").withIndex("by_workspace_status", (q) => q.eq("workspaceId", args.workspaceId)).collect(),
      ctx.db.query("backupSnapshots").withIndex("by_workspace_requested", (q) => q.eq("workspaceId", args.workspaceId)).order("desc").take(10),
      ctx.db.query("restoreDrills").withIndex("by_workspace_requested", (q) => q.eq("workspaceId", args.workspaceId)).order("desc").take(10),
      ctx.db.query("creditAccounts").withIndex("by_workspace", (q) => q.eq("workspaceId", args.workspaceId)).unique(),
    ]);
    const terminal = jobs.filter((job) => ["succeeded", "failed", "canceled"].includes(job.status));
    const failed = terminal.filter((job) => job.status === "failed").length;
    const oldestQueuedAt = jobs.filter((job) => job.status === "queued").reduce<number | null>((oldest, job) => oldest === null ? job.createdAt : Math.min(oldest, job.createdAt), null);
    const queueAgeSeconds = oldestQueuedAt === null ? 0 : Math.max(0, Math.round((Date.now() - oldestQueuedAt) / 1000));
    const failureRatePercent = terminal.length === 0 ? 0 : Math.round((failed / terminal.length) * 100);
    const sourceGroups = assessSourceGroups(authoritativeSources, Date.now());
    const blockedRequiredGroups = sourceGroups.filter((group) => group.requiredForRuns && group.state === "blocked");
    const findings = [queueAgeSeconds > 300 ? "QUEUE_AGE_HIGH" : null, failureRatePercent > 10 ? "FAILURE_RATE_HIGH" : null, blockedRequiredGroups.length > 0 ? "AUTHORITATIVE_SOURCES_NOT_READY" : null, !backups.some((item) => item.state === "completed") ? "BACKUP_NOT_VERIFIED" : null, !drills.some((item) => item.state === "passed") ? "RESTORE_DRILL_NOT_VERIFIED" : null, account?.status !== "active" ? "CREDIT_ACCOUNT_INACTIVE" : null].filter((item): item is string => item !== null);
    return { marker: "OPERATIONS_HEALTH_EXPLAINED" as const, status: findings.some((item) => item !== "BACKUP_NOT_VERIFIED" && item !== "RESTORE_DRILL_NOT_VERIFIED") ? "degraded" as const : findings.length ? "attention" as const : "healthy" as const, queue: { queued: jobs.filter((job) => job.status === "queued").length, running: jobs.filter((job) => job.status === "running").length, queueAgeSeconds }, reliability: { terminalJobs: terminal.length, failedJobs: failed, failureRatePercent }, connectors: { ready: connectors.filter((item) => item.status === "ready").length, setupRequired: connectors.filter((item) => item.status === "setup-required").length }, sourceAssurance: { configuredSources: authoritativeSources.length, requiredGroups: sourceGroups.filter((group) => group.requiredForRuns).length, readyRequiredGroups: sourceGroups.filter((group) => group.requiredForRuns && group.state === "ready").length, blockedRequiredGroups }, latestBackup: backups[0] ?? null, latestRestoreDrill: drills[0] ?? null, findings };
  },
});

/** Requests an encrypted object-store backup without accepting embedded credentials. */
export const requestBackup = mutation({
  args: { workspaceId: v.id("workspaces"), objectRef: v.string() },
  handler: async (ctx, args) => {
    await requireWorkspaceRole(ctx, args.workspaceId, "admin");
    const objectRef = safeObjectRef(args.objectRef);
    const snapshotId = await ctx.db.insert("backupSnapshots", { workspaceId: args.workspaceId, objectRef, state: "requested", schemaVersion: "agent-oven.backup.v1", requestedAt: Date.now() });
    return { marker: "BACKUP_EXPORT_REQUESTED" as const, credentialMarker: "RAW_CREDENTIAL_ABSENT" as const, snapshotId };
  },
});

/** Requests a restore drill against one worker-confirmed snapshot. */
export const requestRestoreDrill = mutation({
  args: { snapshotId: v.id("backupSnapshots"), targetEnvironment: v.string() },
  handler: async (ctx, args) => {
    const snapshot = await ctx.db.get(args.snapshotId);
    if (!snapshot || snapshot.state !== "completed") throw new Error("E_BACKUP_NOT_RESTORABLE");
    await requireWorkspaceRole(ctx, snapshot.workspaceId, "admin");
    const targetEnvironment = assertText(args.targetEnvironment, "target_environment", 120);
    if (!/^(?:ephemeral|staging)-/.test(targetEnvironment)) throw new Error("E_RESTORE_TARGET_NOT_ISOLATED");
    const drillId = await ctx.db.insert("restoreDrills", { workspaceId: snapshot.workspaceId, backupSnapshotId: snapshot._id, targetEnvironment, state: "requested", requestedAt: Date.now() });
    return { marker: "RESTORE_DRILL_REQUESTED" as const, drillId };
  },
});

/** Completes a backup from the trusted worker plane using manifest evidence only. */
export const completeBackup = internalMutation({
  args: { snapshotId: v.id("backupSnapshots"), recordCount: v.number(), manifestDigest: v.string() },
  handler: async (ctx, args) => {
    const snapshot = await ctx.db.get(args.snapshotId);
    if (!snapshot || snapshot.state !== "requested") throw new Error("E_BACKUP_NOT_PENDING");
    assertIntegerRange(args.recordCount, "record_count", 1, 1000000000);
    const manifestDigest = assertText(args.manifestDigest, "manifest_digest", 120);
    const now = Date.now();
    await ctx.db.patch(snapshot._id, { state: "completed", recordCount: args.recordCount, manifestDigest, completedAt: now });
    return { marker: "BACKUP_EXPORT_COMPLETED" as const, snapshotId: snapshot._id, manifestDigest };
  },
});

/** Records measured restore outcomes and appends evidence only when every invariant passes. */
export const completeRestoreDrill = internalMutation({
  args: { drillId: v.id("restoreDrills"), rowCountMatched: v.boolean(), receiptChainVerified: v.boolean(), tenantIsolationVerified: v.boolean(), rtoSeconds: v.number(), rpoSeconds: v.number() },
  handler: async (ctx, args) => {
    const drill = await ctx.db.get(args.drillId);
    if (!drill || drill.state !== "requested") throw new Error("E_RESTORE_DRILL_NOT_PENDING");
    assertIntegerRange(args.rtoSeconds, "rto_seconds", 0, 86400);
    assertIntegerRange(args.rpoSeconds, "rpo_seconds", 0, 86400);
    const passed = args.rowCountMatched && args.receiptChainVerified && args.tenantIsolationVerified;
    const now = Date.now();
    await ctx.db.patch(drill._id, { state: passed ? "passed" : "failed", rowCountMatched: args.rowCountMatched, receiptChainVerified: args.receiptChainVerified, tenantIsolationVerified: args.tenantIsolationVerified, rtoSeconds: args.rtoSeconds, rpoSeconds: args.rpoSeconds, completedAt: now });
    if (passed) {
      const previous = await ctx.db.query("receipts").withIndex("by_workspace_created", (q) => q.eq("workspaceId", drill.workspaceId)).order("desc").first();
      const fingerprint = receiptFingerprint([String(drill._id), String(drill.backupSnapshotId), String(args.rtoSeconds), String(args.rpoSeconds), String(now)]);
      await ctx.db.insert("receipts", { workspaceId: drill.workspaceId, type: "platform-credit", event: "restore-drill.passed", fingerprint, previousFingerprint: previous?.fingerprint, signatureState: "unsigned", createdAt: now });
      return { marker: "RESTORE_DRILL_PASSED" as const, fingerprint, rtoSeconds: args.rtoSeconds, rpoSeconds: args.rpoSeconds };
    }
    return { marker: "RESTORE_DRILL_FAILED" as const, fingerprint: null, rtoSeconds: args.rtoSeconds, rpoSeconds: args.rpoSeconds };
  },
});
