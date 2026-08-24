import { v } from "convex/values";
import type { Id } from "./_generated/dataModel";
import type { MutationCtx } from "./_generated/server";
import { internalMutation, mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";
import { assertIntegerRange, assertText, receiptFingerprint } from "./domain";
import { assessSourceGroups, evaluateSourceState, validateAuthoritativeLocator, validateOpaqueSourceReference } from "../runtime/sourceAssurance";

export const sourceAuthorityCategory = v.union(v.literal("primary-law"), v.literal("official-regulator"), v.literal("official-registry"), v.literal("licensed-system-of-record"), v.literal("secondary-corroboration"));
const sourceRole = v.union(v.literal("primary"), v.literal("fallback"), v.literal("corroboration"));
const failureCode = v.union(v.literal("timeout"), v.literal("authentication"), v.literal("authorization"), v.literal("rate-limited"), v.literal("upstream-unavailable"), v.literal("invalid-response"), v.literal("license-unavailable"), v.literal("unknown"));

/** Throws before job or credit persistence when a required authoritative group is not ready. */
export async function assertRequiredSourcesReady(ctx: MutationCtx, agentSpecId: Id<"agentSpecs">, now: number) {
  const sources = await ctx.db.query("authoritativeSources").withIndex("by_agent_key", (q) => q.eq("agentSpecId", agentSpecId)).collect();
  const groups = assessSourceGroups(sources, now);
  const blocked = groups.filter((group) => group.requiredForRuns && group.state === "blocked");
  if (blocked.length > 0) {
    const reasons = blocked.map((group) => `${group.sourceGroup}:${group.reason}`).join(",");
    throw new Error(`E_AUTHORITATIVE_SOURCES_NOT_READY:${reasons}`);
  }
  return { marker: "AUTHORITATIVE_SOURCES_READY" as const, evaluatedAt: now, groups };
}

/** Configures credential-free authoritative metadata; trusted-worker validation activates the source. */
export const configure = mutation({
  args: {
    agentSpecId: v.id("agentSpecs"), sourceKey: v.string(), label: v.string(), jurisdiction: v.string(), publisher: v.string(), sourceGroup: v.string(),
    authorityCategory: sourceAuthorityCategory, sourceRole, canonicalLocator: v.string(), endpointRef: v.optional(v.string()), licenseRef: v.optional(v.string()),
    freshnessSloSeconds: v.number(), maximumAgeSeconds: v.number(), minimumAuthoritativeSources: v.number(), requiredForRuns: v.boolean(),
  },
  handler: async (ctx, args) => {
    const agent = await ctx.db.get(args.agentSpecId);
    if (!agent) throw new Error("E_AGENT_NOT_FOUND");
    await requireWorkspaceRole(ctx, agent.workspaceId, "admin");
    const sourceKey = assertText(args.sourceKey, "source_key", 120);
    const label = assertText(args.label, "source_label", 120);
    const jurisdiction = assertText(args.jurisdiction, "source_jurisdiction", 120);
    const publisher = assertText(args.publisher, "source_publisher", 160);
    const sourceGroup = assertText(args.sourceGroup, "source_group", 120);
    const canonicalLocator = validateAuthoritativeLocator(args.canonicalLocator);
    const endpointRef = args.endpointRef ? validateOpaqueSourceReference(args.endpointRef) : undefined;
    const licenseRef = args.licenseRef ? validateOpaqueSourceReference(args.licenseRef) : undefined;
    assertIntegerRange(args.freshnessSloSeconds, "freshness_slo_seconds", 60, 2_592_000);
    assertIntegerRange(args.maximumAgeSeconds, "maximum_age_seconds", args.freshnessSloSeconds, 7_776_000);
    assertIntegerRange(args.minimumAuthoritativeSources, "minimum_authoritative_sources", 1, 5);
    if (args.authorityCategory === "secondary-corroboration" && args.sourceRole !== "corroboration") throw new Error("E_SECONDARY_SOURCE_ROLE_INVALID");

    const peers = await ctx.db.query("authoritativeSources").withIndex("by_agent_group", (q) => q.eq("agentSpecId", agent._id).eq("sourceGroup", sourceGroup)).collect();
    const conflicting = peers.find((peer) => peer.sourceKey !== sourceKey && peer.minimumAuthoritativeSources !== args.minimumAuthoritativeSources);
    if (conflicting) throw new Error("E_SOURCE_GROUP_MINIMUM_CONFLICT");
    const canonical = JSON.stringify({ authorityCategory: args.authorityCategory, canonicalLocator, endpointRef: endpointRef ?? null, freshnessSloSeconds: args.freshnessSloSeconds, jurisdiction, label, licenseRef: licenseRef ?? null, maximumAgeSeconds: args.maximumAgeSeconds, minimumAuthoritativeSources: args.minimumAuthoritativeSources, publisher, requiredForRuns: args.requiredForRuns, sourceGroup, sourceKey, sourceRole: args.sourceRole });
    const configDigest = receiptFingerprint([canonical]);
    const existing = await ctx.db.query("authoritativeSources").withIndex("by_agent_key", (q) => q.eq("agentSpecId", agent._id).eq("sourceKey", sourceKey)).unique();
    const now = Date.now();
    const unchanged = existing?.configDigest === configDigest;
    const record = { workspaceId: agent.workspaceId, agentSpecId: agent._id, sourceKey, label, jurisdiction, publisher, sourceGroup, authorityCategory: args.authorityCategory, sourceRole: args.sourceRole, canonicalLocator, endpointRef, licenseRef, freshnessSloSeconds: args.freshnessSloSeconds, maximumAgeSeconds: args.maximumAgeSeconds, minimumAuthoritativeSources: args.minimumAuthoritativeSources, requiredForRuns: args.requiredForRuns, configDigest, status: unchanged && existing ? existing.status : "setup-required" as const, lastObservedAt: unchanged && existing ? existing.lastObservedAt : undefined, lastSuccessfulAt: unchanged && existing ? existing.lastSuccessfulAt : undefined, lastContentDigest: unchanged && existing ? existing.lastContentDigest : undefined, consecutiveFailures: unchanged && existing ? existing.consecutiveFailures : 0, updatedAt: now };
    const sourceId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("authoritativeSources", record);
    await ctx.db.insert("auditEvents", { workspaceId: agent.workspaceId, actor: "source-assurance@factory.local", event: "authoritative-source.configured", targetType: "authoritativeSource", targetId: String(sourceId), detail: `${args.authorityCategory} source ${sourceKey} configured without raw credentials; trusted-worker validation required.`, createdAt: now });
    return { marker: "AUTHORITATIVE_SOURCE_CONFIGURED" as const, sourceId, configDigest, status: record.status };
  },
});

/** Lists exact source and group readiness after workspace authorization. */
export const listReadiness = query({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const agent = await ctx.db.get(args.agentSpecId);
    if (!agent) throw new Error("E_AGENT_NOT_FOUND");
    await requireWorkspaceRole(ctx, agent.workspaceId, "viewer");
    const now = Date.now();
    const sources = await ctx.db.query("authoritativeSources").withIndex("by_agent_key", (q) => q.eq("agentSpecId", agent._id)).collect();
    return { marker: "SOURCE_ASSURANCE_STATUS_UI" as const, governance: "supervised source assurance" as const, evaluatedAt: now, sources: sources.map((source) => ({ ...source, assurance: evaluateSourceState(source, now) })), groups: assessSourceGroups(sources, now) };
  },
});

/** Returns credential-free source definitions to an authenticated workspace worker. */
export const listWorkerDefinitions = query({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const agent = await ctx.db.get(args.agentSpecId);
    if (!agent) throw new Error("E_AGENT_NOT_FOUND");
    await requireWorkspaceRole(ctx, agent.workspaceId, "operator");
    const sources = await ctx.db.query("authoritativeSources").withIndex("by_agent_key", (q) => q.eq("agentSpecId", agent._id)).collect();
    return { marker: "SOURCE_WORKER_DEFINITIONS" as const, posture: "deployment required" as const, sources: sources.filter((source) => source.status !== "disabled").map((source) => ({ sourceId: source._id, configDigest: source.configDigest, canonicalLocator: source.canonicalLocator, endpointRef: source.endpointRef, freshnessSloSeconds: source.freshnessSloSeconds })) };
  },
});

type ObservationInput = { sourceId: Id<"authoritativeSources">; observationKey: string; outcome: "success" | "failure"; observedAt: number; latencyMs: number; sourcePublishedAt?: number; contentDigest?: string; failureCode?: "timeout" | "authentication" | "authorization" | "rate-limited" | "upstream-unavailable" | "invalid-response" | "license-unavailable" | "unknown" };

async function persistObservation(ctx: MutationCtx, args: ObservationInput) {
  const source = await ctx.db.get(args.sourceId);
  if (!source) throw new Error("E_AUTHORITATIVE_SOURCE_NOT_FOUND");
  const observationKey = assertText(args.observationKey, "observation_key", 160);
  assertIntegerRange(args.latencyMs, "source_latency_ms", 0, 300_000);
  if (!Number.isFinite(args.observedAt) || args.observedAt < 0) throw new Error("E_INVALID_OBSERVED_AT");
  if (args.sourcePublishedAt !== undefined && (!Number.isFinite(args.sourcePublishedAt) || args.sourcePublishedAt < 0 || args.sourcePublishedAt > args.observedAt)) throw new Error("E_INVALID_SOURCE_PUBLISHED_AT");
  const existing = await ctx.db.query("sourceObservations").withIndex("by_source_key", (q) => q.eq("sourceId", source._id).eq("observationKey", observationKey)).unique();
  if (existing) return { marker: "SOURCE_OBSERVATION_REPLAY" as const, observationId: existing._id, status: source.status };
  if (args.outcome === "failure" && !args.failureCode) throw new Error("E_SOURCE_FAILURE_CODE_REQUIRED");
  if (args.outcome === "success" && args.failureCode) throw new Error("E_SOURCE_FAILURE_CODE_FORBIDDEN");
  const contentDigest = args.contentDigest ? assertText(args.contentDigest, "source_content_digest", 160) : undefined;
  const now = Date.now();
  const observationId = await ctx.db.insert("sourceObservations", { workspaceId: source.workspaceId, agentSpecId: source.agentSpecId, sourceId: source._id, observationKey, outcome: args.outcome, observedAt: args.observedAt, latencyMs: args.latencyMs, sourcePublishedAt: args.sourcePublishedAt, contentDigest, failureCode: args.failureCode, createdAt: now });
  await ctx.db.patch(source._id, args.outcome === "success" ? { status: "ready", lastObservedAt: args.observedAt, lastSuccessfulAt: args.observedAt, lastContentDigest: contentDigest, consecutiveFailures: 0, updatedAt: now } : { lastObservedAt: args.observedAt, consecutiveFailures: source.consecutiveFailures + 1, updatedAt: now });
  return { marker: "SOURCE_OBSERVATION_RECORDED" as const, observationId, status: args.outcome === "success" ? "ready" as const : source.status };
}

/** Accepts a digest-pinned observation from an authenticated operator worker. */
export const recordWorkerObservation = mutation({
  args: { sourceId: v.id("authoritativeSources"), expectedConfigDigest: v.string(), observationKey: v.string(), outcome: v.union(v.literal("success"), v.literal("failure")), observedAt: v.number(), latencyMs: v.number(), sourcePublishedAt: v.optional(v.number()), contentDigest: v.optional(v.string()), failureCode: v.optional(failureCode) },
  handler: async (ctx, args) => {
    const source = await ctx.db.get(args.sourceId);
    if (!source) throw new Error("E_AUTHORITATIVE_SOURCE_NOT_FOUND");
    await requireWorkspaceRole(ctx, source.workspaceId, "operator");
    if (source.configDigest !== args.expectedConfigDigest) throw new Error("E_AUTHORITATIVE_SOURCE_DIGEST_MISMATCH");
    const { expectedConfigDigest: _expected, ...observation } = args;
    return persistObservation(ctx, observation);
  },
});

/** Disables a source while retaining its observation and audit history. */
export const disable = mutation({
  args: { sourceId: v.id("authoritativeSources") },
  handler: async (ctx, args) => {
    const source = await ctx.db.get(args.sourceId);
    if (!source) throw new Error("E_AUTHORITATIVE_SOURCE_NOT_FOUND");
    await requireWorkspaceRole(ctx, source.workspaceId, "admin");
    await ctx.db.patch(source._id, { status: "disabled", updatedAt: Date.now() });
    return { marker: "AUTHORITATIVE_SOURCE_DISABLED" as const, sourceId: source._id };
  },
});

/** Records one idempotent, bounded observation from the trusted worker plane. */
export const recordObservation = internalMutation({
  args: { sourceId: v.id("authoritativeSources"), observationKey: v.string(), outcome: v.union(v.literal("success"), v.literal("failure")), observedAt: v.number(), latencyMs: v.number(), sourcePublishedAt: v.optional(v.number()), contentDigest: v.optional(v.string()), failureCode: v.optional(failureCode) },
  handler: persistObservation,
});
