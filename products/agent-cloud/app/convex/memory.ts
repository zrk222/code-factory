import { v } from "convex/values";
import type { Doc } from "./_generated/dataModel";
import type { MutationCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import {
  assertIntegerRange,
  assertText,
  canonicalMemoryExport,
  classifyMemoryContent,
  receiptFingerprint,
  toMemoryExportRecords,
} from "./domain";
import { requireWorkspaceRole } from "./access";

const DAY_MS = 86400000;
const POLICY_VERSION = "memory-policy.v1" as const;

function exportPayload(memories: Doc<"memories">[]) {
  const records = toMemoryExportRecords(memories.map((memory) => ({
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
  const canonical = canonicalMemoryExport(records);
  return {
    marker: "MEMORY_EXPORT_READY" as const,
    sanitizedMarker: "MEMORY_EXPORT_SANITIZED" as const,
    authorityMarker: "MEMORY_AUTHORITY_SEPARATED" as const,
    canonical,
    digest: receiptFingerprint([canonical]),
    records,
  };
}

async function eraseRecord(
  ctx: MutationCtx,
  memory: Doc<"memories">,
  reason: string,
  event: "memory.deleted" | "memory.retention-erased",
  now: number,
) {
  await ctx.db.patch(memory._id, {
    subject: "[erased]",
    content: "",
    source: "[erased]",
    purpose: "[erased]",
    provenance: "[erased]",
    confidence: 0,
    deletionReason: reason,
    deletedAt: now,
    policyVersion: POLICY_VERSION,
  });
  const previous = await ctx.db
    .query("receipts")
    .withIndex("by_workspace_created", (q) => q.eq("workspaceId", memory.workspaceId))
    .order("desc")
    .first();
  const fingerprint = receiptFingerprint([String(memory._id), event, String(now)]);
  await ctx.db.insert("receipts", {
    workspaceId: memory.workspaceId,
    memoryId: memory._id,
    type: "memory-deletion",
    event,
    fingerprint,
    previousFingerprint: previous?.fingerprint,
    signatureState: "unsigned",
    createdAt: now,
  });
  await ctx.db.insert("auditEvents", {
    workspaceId: memory.workspaceId,
    actor: event === "memory.deleted" ? "admin@factory.local" : "retention@factory.local",
    event,
    targetType: "memory",
    targetId: String(memory._id),
    detail: "Memory content erased under memory-policy.v1; non-sensitive tombstone retained.",
    createdAt: now,
  });
  return fingerprint;
}

export const add = mutation({
  args: {
    agentSpecId: v.id("agentSpecs"),
    subject: v.string(),
    content: v.string(),
    source: v.string(),
    purpose: v.string(),
    provenance: v.string(),
    confidence: v.number(),
    retentionDays: v.number(),
  },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "operator");
    assertIntegerRange(args.confidence, "confidence", 0, 100);
    assertIntegerRange(args.retentionDays, "retention", 1, 3650);
    const content = assertText(args.content, "content", 2000);
    const classification = classifyMemoryContent(content);
    const memoryId = await ctx.db.insert("memories", {
      workspaceId: spec.workspaceId,
      agentSpecId: spec._id,
      subject: assertText(args.subject, "subject", 200),
      content,
      source: assertText(args.source, "source", 300),
      purpose: assertText(args.purpose, "purpose", 300),
      provenance: assertText(args.provenance, "provenance", 500),
      confidence: args.confidence,
      retentionDays: args.retentionDays,
      trustLabel: "untrusted-context",
      policyVersion: POLICY_VERSION,
      ...classification,
      createdAt: Date.now(),
    });
    await ctx.db.insert("auditEvents", {
      workspaceId: spec.workspaceId,
      actor: "admin@factory.local",
      event: "memory.created",
      targetType: "memory",
      targetId: String(memoryId),
      detail: `Memory stored as untrusted context with provenance and memory-policy.v1; safety=${classification.safetyState}.`,
      createdAt: Date.now(),
    });
    return {
      marker: "MEMORY_PROVENANCE_BOUND" as const,
      authorityMarker: "MEMORY_AUTHORITY_SEPARATED" as const,
      policyVersion: POLICY_VERSION,
      safetyMarker: classification.safetyState === "eligible" ? "MEMORY_RECALL_ELIGIBLE" as const : "MEMORY_QUARANTINED" as const,
      auditMarker: "MEMORY_CONTENT_REDACTED_FROM_AUDIT" as const,
      memoryId,
    };
  },
});

export const correct = mutation({
  args: { memoryId: v.id("memories"), content: v.string(), reason: v.string() },
  handler: async (ctx, args) => {
    const memory = await ctx.db.get(args.memoryId);
    if (!memory) throw new Error("E_MEMORY_NOT_FOUND");
    await requireWorkspaceRole(ctx, memory.workspaceId, "admin");
    if (memory.deletedAt !== undefined || memory.supersededAt !== undefined) throw new Error("E_MEMORY_NOT_ACTIVE");
    const content = assertText(args.content, "content", 2000);
    const reason = assertText(args.reason, "correction_reason", 500);
    const classification = classifyMemoryContent(content);
    const now = Date.now();
    const successorId = await ctx.db.insert("memories", {
      workspaceId: memory.workspaceId,
      agentSpecId: memory.agentSpecId,
      subject: memory.subject,
      content,
      source: memory.source,
      purpose: memory.purpose,
      provenance: `Corrected under memory-policy.v1: ${reason}`,
      confidence: memory.confidence,
      retentionDays: memory.retentionDays,
      trustLabel: "untrusted-context",
      policyVersion: POLICY_VERSION,
      ...classification,
      supersedesMemoryId: memory._id,
      createdAt: now,
    });
    await ctx.db.patch(memory._id, { supersededAt: now, supersededByMemoryId: successorId, policyVersion: POLICY_VERSION });
    const previous = await ctx.db
      .query("receipts")
      .withIndex("by_workspace_created", (q) => q.eq("workspaceId", memory.workspaceId))
      .order("desc")
      .first();
    const fingerprint = receiptFingerprint([String(memory._id), String(successorId), "memory.corrected", String(now)]);
    await ctx.db.insert("receipts", {
      workspaceId: memory.workspaceId,
      memoryId: successorId,
      type: "memory-correction",
      event: "memory.corrected",
      fingerprint,
      previousFingerprint: previous?.fingerprint,
      signatureState: "unsigned",
      createdAt: now,
    });
    await ctx.db.insert("auditEvents", {
      workspaceId: memory.workspaceId,
      actor: "admin@factory.local",
      event: "memory.corrected",
      targetType: "memory",
      targetId: String(successorId),
      detail: "Correction appended as a successor; predecessor preserved as superseded history.",
      createdAt: now,
    });
    return {
      marker: "MEMORY_CORRECTED" as const,
      authorityMarker: "MEMORY_AUTHORITY_SEPARATED" as const,
      predecessorId: memory._id,
      successorId,
      fingerprint,
      safetyMarker: classification.safetyState === "eligible" ? "MEMORY_RECALL_ELIGIBLE" as const : "MEMORY_QUARANTINED" as const,
      auditMarker: "MEMORY_CONTENT_REDACTED_FROM_AUDIT" as const,
    };
  },
});

export const remove = mutation({
  args: { memoryId: v.id("memories"), reason: v.optional(v.string()) },
  handler: async (ctx, args) => {
    const memory = await ctx.db.get(args.memoryId);
    if (!memory) throw new Error("E_MEMORY_NOT_FOUND");
    await requireWorkspaceRole(ctx, memory.workspaceId, "admin");
    if (memory.deletedAt !== undefined) throw new Error("E_MEMORY_ALREADY_DELETED");
    const reason = assertText(args.reason ?? "Admin-requested erasure", "deletion_reason", 500);
    const fingerprint = await eraseRecord(ctx, memory, reason, "memory.deleted", Date.now());
    return {
      marker: "MEMORY_CONTENT_ERASED" as const,
      legacyMarker: "MEMORY_TOMBSTONED" as const,
      erasedMarker: "MEMORY_ERASED" as const,
      fingerprint,
    };
  },
});

export const enforceRetention = mutation({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "admin");
    const now = Date.now();
    const records = await ctx.db
      .query("memories")
      .withIndex("by_workspace_agent", (q) => q.eq("workspaceId", spec.workspaceId).eq("agentSpecId", spec._id))
      .take(1000);
    const expired = records.filter((record) => record.deletedAt === undefined && record.createdAt + record.retentionDays * DAY_MS <= now);
    for (const record of expired) {
      await eraseRecord(ctx, record, "Retention period elapsed", "memory.retention-erased", now);
    }
    return {
      marker: "MEMORY_RETENTION_ENFORCED" as const,
      expiredMarker: "RETENTION_EXPIRED" as const,
      receiptMarker: "RETENTION_RECEIPTS_EXACT" as const,
      inspected: records.length,
      erased: expired.length,
      receiptsAppended: expired.length,
    };
  },
});

export const listActive = query({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "viewer");
    const records = await ctx.db
      .query("memories")
      .withIndex("by_workspace_agent", (q) => q.eq("workspaceId", spec.workspaceId).eq("agentSpecId", spec._id))
      .collect();
    return records.filter((record) => record.deletedAt === undefined && record.supersededAt === undefined);
  },
});

/** Recalls only active, eligible records in an exact AgentSpec-derived scope. */
export const recallScoped = query({
  args: {
    agentSpecId: v.id("agentSpecs"),
    subject: v.string(),
    purpose: v.string(),
    limit: v.number(),
  },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "viewer");
    const subject = assertText(args.subject, "subject", 200).toLocaleLowerCase("en-US");
    const purpose = assertText(args.purpose, "purpose", 300).toLocaleLowerCase("en-US");
    assertIntegerRange(args.limit, "limit", 1, 20);
    const records = await ctx.db
      .query("memories")
      .withIndex("by_workspace_agent", (q) => q.eq("workspaceId", spec.workspaceId).eq("agentSpecId", spec._id))
      .collect();
    const active = records.filter((record) => record.deletedAt === undefined && record.supersededAt === undefined);
    const quarantinedExcluded = active.filter((record) => record.safetyState === "quarantined").length;
    const eligible = active.filter((record) => record.safetyState !== "quarantined");
    const scoped = eligible.filter((record) =>
      record.subject.trim().toLocaleLowerCase("en-US") === subject
      && record.purpose.trim().toLocaleLowerCase("en-US") === purpose
    );
    const recalled = scoped
      .sort((left, right) => right.confidence - left.confidence || right.createdAt - left.createdAt)
      .slice(0, args.limit)
      .map((record) => ({
        subject: record.subject,
        content: record.content,
        source: record.source,
        purpose: record.purpose,
        provenance: record.provenance,
        confidence: record.confidence,
        policyVersion: record.policyVersion ?? POLICY_VERSION,
        trustLabel: record.trustLabel,
        safetyState: "eligible" as const,
        createdAt: record.createdAt,
        why: "Matched this AgentSpec, exact subject, and exact purpose; ranked by confidence and recency.",
      }));
    return {
      marker: "MEMORY_RECALL_SCOPED" as const,
      quarantineMarker: "MEMORY_QUARANTINE_ENFORCED" as const,
      authorityMarker: "MEMORY_AUTHORITY_SEPARATED" as const,
      explanationMarker: "MEMORY_RECALL_EXPLAINED" as const,
      scope: { subject: args.subject.trim(), purpose: args.purpose.trim(), agentVersion: spec.version },
      counts: {
        considered: active.length,
        quarantinedExcluded,
        scopeExcluded: eligible.length - scoped.length,
        returned: recalled.length,
      },
      recalled,
    };
  },
});

export const exportGoverned = query({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "viewer");
    const memories = await ctx.db
      .query("memories")
      .withIndex("by_workspace_agent", (q) => q.eq("workspaceId", spec.workspaceId).eq("agentSpecId", spec._id))
      .collect();
    return exportPayload(memories);
  },
});
