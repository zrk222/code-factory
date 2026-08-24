import { v } from "convex/values";
import type { MutationCtx } from "./_generated/server";
import { internalMutation, mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";
import { assertIntegerRange, assertText, receiptFingerprint } from "./domain";
import { evaluateCompliancePath, redactOperationalText } from "./agentIntelligenceDomain";

const updateChannel = v.union(v.literal("frozen"), v.literal("managed"));
const progressPhase = v.union(v.literal("plan"), v.literal("gather"), v.literal("sufficiency"), v.literal("synthesize"), v.literal("act"), v.literal("validate"), v.literal("complete"));
const scoreComponent = v.union(v.literal("retrieval"), v.literal("source-selection"), v.literal("planning"), v.literal("synthesis"), v.literal("accuracy"), v.literal("completeness"), v.literal("objectivity"), v.literal("citation-quality"), v.literal("connector-reliability"), v.literal("compliance"));
const rulePredicate = v.union(v.literal("required-before"), v.literal("forbidden-after"), v.literal("requires-human-gate"), v.literal("max-count"));

const clean = (value: string, name: string, max: number) => assertText(redactOperationalText(value), name, max);
const cleanRef = (value: string, name: string) => {
  const ref = assertText(value, name, 500);
  if (/\/\/[^/\s]+:[^/@\s]+@/i.test(ref) || /[?&](?:token|key|secret|password)=/i.test(ref)) throw new Error("E_TRACE_CREDENTIAL_FORBIDDEN");
  return ref;
};
const strings = (values: string[], name: string, maxItems: number, maxLength = 160) => {
  if (values.length > maxItems) throw new Error(`E_INVALID_${name.toUpperCase()}`);
  return [...new Set(values.map((value) => assertText(value, name, maxLength)))];
};

type SearchPolicyInput = {
  recencyDays?: number; sourceFromDate?: string; sourceToDate?: string;
  country?: string; region?: string; city?: string;
  latitude?: number; longitude?: number; radiusKm?: number;
};

const optionalText = (value: string | undefined, name: string, max: number) => value === undefined ? undefined : assertText(value, name, max);

function normalizeDateRange(input: SearchPolicyInput) {
  const sourceFromDate = optionalText(input.sourceFromDate, "source_from_date", 10);
  const sourceToDate = optionalText(input.sourceToDate, "source_to_date", 10);
  if (sourceFromDate && !/^\d{4}-\d{2}-\d{2}$/.test(sourceFromDate)) throw new Error("E_SOURCE_DATE_RANGE_INVALID");
  if (sourceToDate && !/^\d{4}-\d{2}-\d{2}$/.test(sourceToDate)) throw new Error("E_SOURCE_DATE_RANGE_INVALID");
  if (sourceFromDate && sourceToDate && sourceFromDate > sourceToDate) throw new Error("E_SOURCE_DATE_RANGE_INVALID");
  return { sourceFromDate, sourceToDate };
}

function normalizeCoordinates(input: SearchPolicyInput) {
  if ((input.latitude === undefined) !== (input.longitude === undefined)) throw new Error("E_LOCATION_COORDINATES_INCOMPLETE");
  if (input.latitude !== undefined && (input.latitude < -90 || input.latitude > 90)) throw new Error("E_INVALID_LATITUDE");
  if (input.longitude !== undefined && (input.longitude < -180 || input.longitude > 180)) throw new Error("E_INVALID_LONGITUDE");
  if (input.radiusKm !== undefined) assertIntegerRange(input.radiusKm, "radius_km", 1, 10000);
  return { latitude: input.latitude, longitude: input.longitude, radiusKm: input.radiusKm };
}

function normalizeSearchPolicy(input: SearchPolicyInput) {
  if (input.recencyDays !== undefined) assertIntegerRange(input.recencyDays, "recency_days", 1, 3650);
  return { recencyDays: input.recencyDays, ...normalizeDateRange(input), country: optionalText(input.country, "country", 80), region: optionalText(input.region, "region", 120), city: optionalText(input.city, "city", 120), ...normalizeCoordinates(input) };
}

function validateRuleShape(predicate: "required-before" | "forbidden-after" | "requires-human-gate" | "max-count", relatedStep: string | undefined, maxCount: number | undefined) {
  if ((predicate === "required-before" || predicate === "forbidden-after") && !relatedStep) throw new Error("E_RULE_RELATED_STEP_REQUIRED");
  if (predicate === "max-count") assertIntegerRange(maxCount ?? -1, "rule_max_count", 0, 100);
}

function validateUsageBounds(args: { cachedInputTokens: number; inputTokens: number; outputTokens: number; reasoningTokens: number; providerCostMicros: number; latencyMs: number; toolSteps: number }) {
  const values = [["cached_input_tokens", args.cachedInputTokens, 2000000], ["input_tokens", args.inputTokens, 2000000], ["output_tokens", args.outputTokens, 200000], ["reasoning_tokens", args.reasoningTokens, 200000], ["provider_cost_micros", args.providerCostMicros, 1000000000], ["latency_ms", args.latencyMs, 86400000], ["tool_steps", args.toolSteps, 10000]] as const;
  for (const [name, value, max] of values) assertIntegerRange(value, name, 0, max);
}

function assertUsageTotals(policy: { maxInputTokens: number; maxOutputTokens: number; maxReasoningTokens: number; maxSteps: number }, totals: { input: number; output: number; reasoning: number; steps: number }) {
  if (totals.input > policy.maxInputTokens) throw new Error("E_RUNTIME_PRESET_BUDGET_EXCEEDED");
  if (totals.output > policy.maxOutputTokens) throw new Error("E_RUNTIME_PRESET_BUDGET_EXCEEDED");
  if (totals.reasoning > policy.maxReasoningTokens) throw new Error("E_RUNTIME_PRESET_BUDGET_EXCEEDED");
  if (totals.steps > policy.maxSteps) throw new Error("E_RUNTIME_PRESET_BUDGET_EXCEEDED");
}

async function jobForWorker(ctx: MutationCtx, jobId: Parameters<MutationCtx["db"]["get"]>[0]) {
  const job = await ctx.db.get(jobId as never);
  if (!job || !("workspaceId" in job)) throw new Error("E_EXECUTION_JOB_NOT_FOUND");
  return job as any;
}

/** Saves one bounded runtime policy as a draft. */
export const savePreset = mutation({
  args: { agentSpecId: v.id("agentSpecs"), name: v.string(), updateChannel, maxSteps: v.number(), maxInputTokens: v.number(), maxOutputTokens: v.number(), maxReasoningTokens: v.number(), allowedModels: v.array(v.string()), allowedTools: v.array(v.string()), allowedWorkflows: v.array(v.string()), sourceAllowDomains: v.array(v.string()), sourceDenyDomains: v.array(v.string()), recencyDays: v.optional(v.number()), sourceFromDate: v.optional(v.string()), sourceToDate: v.optional(v.string()), country: v.optional(v.string()), region: v.optional(v.string()), city: v.optional(v.string()), latitude: v.optional(v.number()), longitude: v.optional(v.number()), radiusKm: v.optional(v.number()), requireClarification: v.boolean(), rubricVersion: v.string() },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "admin");
    assertIntegerRange(args.maxSteps, "max_steps", 1, 100);
    assertIntegerRange(args.maxInputTokens, "max_input_tokens", 1, 2000000);
    assertIntegerRange(args.maxOutputTokens, "max_output_tokens", 1, 200000);
    assertIntegerRange(args.maxReasoningTokens, "max_reasoning_tokens", 0, 200000);
    const semantic = { name: assertText(args.name, "preset_name", 120), updateChannel: args.updateChannel, maxSteps: args.maxSteps, maxInputTokens: args.maxInputTokens, maxOutputTokens: args.maxOutputTokens, maxReasoningTokens: args.maxReasoningTokens, allowedModels: strings(args.allowedModels, "allowed_model", 20), allowedTools: strings(args.allowedTools, "allowed_tool", 50), allowedWorkflows: strings(args.allowedWorkflows, "allowed_workflow", 20), sourceAllowDomains: strings(args.sourceAllowDomains, "source_allow_domain", 30, 240), sourceDenyDomains: strings(args.sourceDenyDomains, "source_deny_domain", 30, 240), ...normalizeSearchPolicy(args), requireClarification: args.requireClarification, rubricVersion: assertText(args.rubricVersion, "rubric_version", 80) };
    if (semantic.allowedModels.length === 0 || semantic.allowedTools.length === 0 || semantic.allowedWorkflows.length === 0) throw new Error("E_PRESET_ALLOWLIST_REQUIRED");
    const existing = await ctx.db.query("governedRuntimePresets").withIndex("by_agent", (q) => q.eq("agentSpecId", spec._id)).unique();
    const version = (existing?.version ?? 0) + 1;
    const canonical = JSON.stringify(semantic);
    const digest = receiptFingerprint([canonical, String(version)]);
    const record = { workspaceId: spec.workspaceId, agentSpecId: spec._id, ...semantic, version, digest, status: "draft" as const, updatedAt: Date.now(), publishedAt: undefined };
    const presetId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("governedRuntimePresets", record);
    await ctx.db.insert("governedRuntimePresetVersions", { workspaceId: spec.workspaceId, agentSpecId: spec._id, presetId, version, canonical, digest, createdAt: Date.now() });
    return { marker: "GOVERNED_RUNTIME_PRESET_SAVED" as const, presetId, version, digest, status: "draft" as const };
  },
});

/** Publishes the exact current preset version for activation and job pinning. */
export const publishPreset = mutation({
  args: { presetId: v.id("governedRuntimePresets"), expectedDigest: v.string() },
  handler: async (ctx, args) => {
    const preset = await ctx.db.get(args.presetId);
    if (!preset) throw new Error("E_RUNTIME_PRESET_NOT_FOUND");
    await requireWorkspaceRole(ctx, preset.workspaceId, "admin");
    if (preset.status !== "draft" || preset.digest !== args.expectedDigest) throw new Error("E_RUNTIME_PRESET_DIGEST_MISMATCH");
    const now = Date.now();
    const immutable = await ctx.db.query("governedRuntimePresetVersions").withIndex("by_preset_version", (q) => q.eq("presetId", preset._id).eq("version", preset.version)).unique();
    if (!immutable || immutable.digest !== preset.digest) throw new Error("E_RUNTIME_PRESET_VERSION_MISSING");
    await ctx.db.patch(preset._id, { status: "published", publishedAt: now, updatedAt: now });
    await ctx.db.patch(immutable._id, { publishedAt: now });
    return { marker: "GOVERNED_PRESET_PUBLISHED" as const, presetId: preset._id, version: preset.version, digest: preset.digest, updateChannel: preset.updateChannel };
  },
});

/** Reads the current governed runtime preset. */
export const getPreset = query({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "viewer");
    return await ctx.db.query("governedRuntimePresets").withIndex("by_agent", (q) => q.eq("agentSpecId", spec._id)).unique();
  },
});

/** Adds one pre-execution question; required questions block the worker contract until answered. */
export const addClarification = mutation({
  args: { jobId: v.id("executionJobs"), questionId: v.string(), question: v.string(), required: v.boolean() },
  handler: async (ctx, args) => {
    const job = await ctx.db.get(args.jobId);
    if (!job) throw new Error("E_EXECUTION_JOB_NOT_FOUND");
    await requireWorkspaceRole(ctx, job.workspaceId, "operator");
    const questionId = assertText(args.questionId, "question_id", 80);
    const existing = await ctx.db.query("runtimeClarifications").withIndex("by_job_question", (q) => q.eq("executionJobId", job._id).eq("questionId", questionId)).unique();
    if (existing) throw new Error("E_CLARIFICATION_EXISTS");
    const clarificationId = await ctx.db.insert("runtimeClarifications", { workspaceId: job.workspaceId, executionJobId: job._id, questionId, question: clean(args.question, "question", 500), required: args.required, createdAt: Date.now() });
    return { marker: "CLARIFICATION_GATE_CREATED" as const, clarificationId };
  },
});

/** Answers one exact clarification with authenticated operator attribution. */
export const answerClarification = mutation({
  args: { clarificationId: v.id("runtimeClarifications"), answer: v.string() },
  handler: async (ctx, args) => {
    const item = await ctx.db.get(args.clarificationId);
    if (!item) throw new Error("E_CLARIFICATION_NOT_FOUND");
    const authorized = await requireWorkspaceRole(ctx, item.workspaceId, "operator");
    if (item.answer !== undefined) throw new Error("E_CLARIFICATION_ALREADY_ANSWERED");
    await ctx.db.patch(item._id, { answer: clean(args.answer, "clarification_answer", 1000), answeredBy: authorized.tokenIdentifier, answeredAt: Date.now() });
    return { marker: "CLARIFICATION_ANSWERED" as const, clarificationId: item._id };
  },
});

/** Saves a machine-checkable operations-manual rule as a human-reviewable draft. */
export const saveOpsRule = mutation({
  args: { agentSpecId: v.id("agentSpecs"), ruleId: v.string(), description: v.string(), predicate: rulePredicate, subjectStep: v.string(), relatedStep: v.optional(v.string()), maxCount: v.optional(v.number()), sourceMemoryId: v.optional(v.id("memories")) },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    const authorized = await requireWorkspaceRole(ctx, spec.workspaceId, "admin");
    validateRuleShape(args.predicate, args.relatedStep, args.maxCount);
    if (args.sourceMemoryId) {
      const memory = await ctx.db.get(args.sourceMemoryId);
      if (!memory || memory.workspaceId !== spec.workspaceId || memory.agentSpecId !== spec._id) throw new Error("E_RULE_SOURCE_MEMORY_INVALID");
    }
    const ruleId = assertText(args.ruleId, "rule_id", 80);
    const existing = await ctx.db.query("opsManualRules").withIndex("by_agent_rule", (q) => q.eq("agentSpecId", spec._id).eq("ruleId", ruleId)).unique();
    const record = { workspaceId: spec.workspaceId, agentSpecId: spec._id, ruleId, description: clean(args.description, "rule_description", 500), predicate: args.predicate, subjectStep: assertText(args.subjectStep, "subject_step", 80), relatedStep: args.relatedStep ? assertText(args.relatedStep, "related_step", 80) : undefined, maxCount: args.maxCount, sourceMemoryId: args.sourceMemoryId, status: "draft" as const, createdBy: authorized.tokenIdentifier, createdAt: Date.now(), publishedAt: undefined };
    const ruleDocumentId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("opsManualRules", record);
    return { marker: "OPS_MANUAL_RULE_DRAFTED" as const, ruleDocumentId, ruleId };
  },
});

/** Publishes a reviewed rule; no generated rule self-activates. */
export const publishOpsRule = mutation({
  args: { ruleDocumentId: v.id("opsManualRules") },
  handler: async (ctx, args) => {
    const rule = await ctx.db.get(args.ruleDocumentId);
    if (!rule) throw new Error("E_OPS_RULE_NOT_FOUND");
    await requireWorkspaceRole(ctx, rule.workspaceId, "admin");
    await ctx.db.patch(rule._id, { status: "published", publishedAt: Date.now() });
    return { marker: "OPS_MANUAL_RULE_PUBLISHED" as const, ruleId: rule.ruleId };
  },
});

/** Resumes the latest suspended snapshot only when its one exact digest matches. */
export const resumeJob = mutation({
  args: { jobId: v.id("executionJobs"), resumeDigest: v.string() },
  handler: async (ctx, args) => {
    const job = await ctx.db.get(args.jobId);
    if (!job) throw new Error("E_EXECUTION_JOB_NOT_FOUND");
    await requireWorkspaceRole(ctx, job.workspaceId, "operator");
    if (job.status !== "suspended") throw new Error("E_EXECUTION_NOT_SUSPENDED");
    const snapshots = await ctx.db.query("runtimeSnapshots").withIndex("by_job_sequence", (q) => q.eq("executionJobId", job._id)).order("desc").collect();
    const snapshot = snapshots.find((item) => item.status === "suspended");
    if (!snapshot || snapshot.resumeDigest !== args.resumeDigest) throw new Error("E_RESUME_DIGEST_MISMATCH");
    const now = Date.now();
    await ctx.db.patch(snapshot._id, { status: "resumed", resumedAt: now });
    await ctx.db.patch(job._id, { status: "queued" });
    const lease = await ctx.db.query("runtimeLeases").withIndex("by_job", (q) => q.eq("executionJobId", job._id)).unique();
    if (lease) await ctx.db.patch(lease._id, { state: "active", workerId: undefined, expiresAt: now + 5 * 60 * 1000, lastHeartbeatAt: now });
    return { marker: "RUN_SNAPSHOT_RESUMED" as const, jobId: job._id, snapshotId: snapshot._id };
  },
});

/** Returns redacted progress, exact usage, artifacts, scores, snapshots, and clarifications for one run. */
export const runIntelligence = query({
  args: { jobId: v.id("executionJobs") },
  handler: async (ctx, args) => {
    const job = await ctx.db.get(args.jobId);
    if (!job) throw new Error("E_EXECUTION_JOB_NOT_FOUND");
    const authorized = await requireWorkspaceRole(ctx, job.workspaceId, "viewer");
    const [clarifications, progress, findings, usage, artifacts, scores, snapshots] = await Promise.all([
      ctx.db.query("runtimeClarifications").withIndex("by_job_question", (q) => q.eq("executionJobId", job._id)).collect(),
      ctx.db.query("runtimeProgressEvents").withIndex("by_job_sequence", (q) => q.eq("executionJobId", job._id)).collect(),
      ctx.db.query("runtimeFindings").withIndex("by_job", (q) => q.eq("executionJobId", job._id)).collect(),
      ctx.db.query("runtimeUsageRecords").withIndex("by_job", (q) => q.eq("executionJobId", job._id)).collect(),
      ctx.db.query("runtimeArtifacts").withIndex("by_job", (q) => q.eq("executionJobId", job._id)).collect(),
      ctx.db.query("runtimeComponentScores").withIndex("by_job_component", (q) => q.eq("executionJobId", job._id)).collect(),
      ctx.db.query("runtimeSnapshots").withIndex("by_job_sequence", (q) => q.eq("executionJobId", job._id)).collect(),
    ]);
    const canOperate = ["owner", "admin", "operator"].includes(authorized.membership.role);
    return {
      marker: "GOVERNED_RUN_EXPLAINED" as const,
      clarifications: clarifications.map(({ answeredBy: _answeredBy, ...item }) => item),
      progress,
      findings,
      usage,
      artifacts,
      scores,
      snapshots: snapshots.map(({ resumeDigest, ...snapshot }) => canOperate ? { ...snapshot, resumeDigest } : snapshot),
    };
  },
});

export const recordProgress = internalMutation({
  args: { jobId: v.id("executionJobs"), sequence: v.number(), phase: progressPhase, summary: v.string(), evidenceClass: v.union(v.literal("declared"), v.literal("observed"), v.literal("verified")) },
  handler: async (ctx, args) => { const job = await jobForWorker(ctx, args.jobId); assertIntegerRange(args.sequence, "progress_sequence", 1, 10000); const id = await ctx.db.insert("runtimeProgressEvents", { workspaceId: job.workspaceId, executionJobId: args.jobId, sequence: args.sequence, phase: args.phase, summary: clean(args.summary, "progress_summary", 1000), evidenceClass: args.evidenceClass, createdAt: Date.now() }); return { marker: "RUN_PROGRESS_RECORDED" as const, id }; },
});

export const recordFinding = internalMutation({
  args: { jobId: v.id("executionJobs"), title: v.string(), summary: v.string(), sourceRef: v.optional(v.string()), sourceDigest: v.optional(v.string()), contradiction: v.boolean() },
  handler: async (ctx, args) => { const job = await jobForWorker(ctx, args.jobId); const id = await ctx.db.insert("runtimeFindings", { workspaceId: job.workspaceId, executionJobId: args.jobId, title: clean(args.title, "finding_title", 160), summary: clean(args.summary, "finding_summary", 1000), sourceRef: args.sourceRef ? cleanRef(args.sourceRef, "source_ref") : undefined, sourceDigest: args.sourceDigest ? assertText(args.sourceDigest, "source_digest", 120) : undefined, contradiction: args.contradiction, createdAt: Date.now() }); return { marker: "RUN_FINDING_RECORDED" as const, id }; },
});

export const recordUsage = internalMutation({
  args: { jobId: v.id("executionJobs"), provider: v.string(), model: v.string(), cachedInputTokens: v.number(), inputTokens: v.number(), outputTokens: v.number(), reasoningTokens: v.number(), providerCostMicros: v.number(), latencyMs: v.number(), toolSteps: v.number() },
  handler: async (ctx, args) => {
    const job = await jobForWorker(ctx, args.jobId);
    if (job.status !== "running") throw new Error("E_EXECUTION_NOT_RUNNING");
    validateUsageBounds(args);
    const provider = assertText(args.provider, "provider", 80);
    const model = assertText(args.model, "model", 120);
    if (job.runtimePresetVersion !== undefined) {
      const preset = await ctx.db.query("governedRuntimePresets").withIndex("by_agent", (q) => q.eq("agentSpecId", job.agentSpecId)).unique();
      if (!preset) throw new Error("E_RUNTIME_PRESET_NOT_FOUND");
      const pinned = await ctx.db.query("governedRuntimePresetVersions").withIndex("by_preset_version", (q) => q.eq("presetId", preset._id).eq("version", job.runtimePresetVersion)).unique();
      if (!pinned || pinned.digest !== job.runtimePresetDigest) throw new Error("E_RUNTIME_PRESET_PIN_INVALID");
      const policy = JSON.parse(pinned.canonical) as { allowedModels: string[]; maxInputTokens: number; maxOutputTokens: number; maxReasoningTokens: number; maxSteps: number };
      if (!policy.allowedModels.includes(`${provider}/${model}`) && !policy.allowedModels.includes(model)) throw new Error("E_RUNTIME_MODEL_NOT_ALLOWED");
      const previous = await ctx.db.query("runtimeUsageRecords").withIndex("by_job", (q) => q.eq("executionJobId", args.jobId)).collect();
      const totals = previous.reduce((sum, item) => ({ input: sum.input + item.inputTokens, output: sum.output + item.outputTokens, reasoning: sum.reasoning + item.reasoningTokens, steps: sum.steps + item.toolSteps }), { input: args.inputTokens, output: args.outputTokens, reasoning: args.reasoningTokens, steps: args.toolSteps });
      assertUsageTotals(policy, totals);
    }
    const id = await ctx.db.insert("runtimeUsageRecords", { workspaceId: job.workspaceId, executionJobId: args.jobId, provider, model, cachedInputTokens: args.cachedInputTokens, inputTokens: args.inputTokens, outputTokens: args.outputTokens, reasoningTokens: args.reasoningTokens, providerCostMicros: args.providerCostMicros, latencyMs: args.latencyMs, toolSteps: args.toolSteps, createdAt: Date.now() });
    return { marker: "EXACT_USAGE_RECORDED" as const, id };
  },
});

export const recordArtifact = internalMutation({
  args: { jobId: v.id("executionJobs"), label: v.string(), objectRef: v.string(), digest: v.string(), mediaType: v.string(), editable: v.boolean() },
  handler: async (ctx, args) => { const job = await jobForWorker(ctx, args.jobId); const id = await ctx.db.insert("runtimeArtifacts", { workspaceId: job.workspaceId, executionJobId: args.jobId, label: clean(args.label, "artifact_label", 160), objectRef: cleanRef(args.objectRef, "artifact_object_ref"), digest: assertText(args.digest, "artifact_digest", 120), mediaType: assertText(args.mediaType, "media_type", 120), editable: args.editable, createdAt: Date.now() }); return { marker: "DURABLE_ARTIFACT_RECORDED" as const, id }; },
});

export const recordScore = internalMutation({
  args: { jobId: v.id("executionJobs"), component: scoreComponent, method: v.union(v.literal("deterministic"), v.literal("model"), v.literal("statistical")), score: v.number(), rubricVersion: v.string(), evidenceDigest: v.string() },
  handler: async (ctx, args) => { const job = await jobForWorker(ctx, args.jobId); assertIntegerRange(args.score, "component_score", 0, 100); const id = await ctx.db.insert("runtimeComponentScores", { workspaceId: job.workspaceId, executionJobId: args.jobId, component: args.component, method: args.method, score: args.score, rubricVersion: assertText(args.rubricVersion, "rubric_version", 80), evidenceDigest: assertText(args.evidenceDigest, "evidence_digest", 120), createdAt: Date.now() }); return { marker: "COMPONENT_SCORE_RECORDED" as const, id }; },
});

export const suspendJob = internalMutation({
  args: { jobId: v.id("executionJobs"), sequence: v.number(), currentStepId: v.string(), executedPath: v.array(v.string()), outputRefs: v.array(v.string()), reason: v.string(), resumeDigest: v.string() },
  handler: async (ctx, args) => { const job = await jobForWorker(ctx, args.jobId); if (job.status !== "running") throw new Error("E_EXECUTION_NOT_RUNNING"); assertIntegerRange(args.sequence, "snapshot_sequence", 1, 10000); const id = await ctx.db.insert("runtimeSnapshots", { workspaceId: job.workspaceId, executionJobId: args.jobId, sequence: args.sequence, currentStepId: assertText(args.currentStepId, "current_step_id", 80), executedPath: strings(args.executedPath, "executed_step", 100, 80), outputRefs: args.outputRefs.map((ref) => cleanRef(ref, "snapshot_output_ref")), reason: clean(args.reason, "snapshot_reason", 500), resumeDigest: assertText(args.resumeDigest, "resume_digest", 120), status: "suspended", createdAt: Date.now() }); await ctx.db.patch(args.jobId, { status: "suspended" }); const lease = await ctx.db.query("runtimeLeases").withIndex("by_job", (q) => q.eq("executionJobId", args.jobId)).unique(); if (lease) await ctx.db.patch(lease._id, { state: "revoked", lastHeartbeatAt: Date.now() }); return { marker: "RUN_SNAPSHOT_SUSPENDED" as const, snapshotId: id }; },
});

export const validateTrace = internalMutation({
  args: { jobId: v.id("executionJobs"), executedPath: v.array(v.string()), humanGates: v.array(v.string()), rubricVersion: v.string(), evidenceDigest: v.string() },
  handler: async (ctx, args) => { const job = await jobForWorker(ctx, args.jobId); const rules = await ctx.db.query("opsManualRules").withIndex("by_agent_rule", (q) => q.eq("agentSpecId", job.agentSpecId)).collect(); const result = evaluateCompliancePath(args.executedPath, args.humanGates, rules.filter((rule) => rule.status === "published")); const score = result.passed ? 100 : 0; await ctx.db.insert("runtimeComponentScores", { workspaceId: job.workspaceId, executionJobId: args.jobId, component: "compliance", method: "deterministic", score, rubricVersion: assertText(args.rubricVersion, "rubric_version", 80), evidenceDigest: assertText(args.evidenceDigest, "evidence_digest", 120), createdAt: Date.now() }); return { marker: "OPS_MANUAL_TRACE_VALIDATED" as const, ...result, score }; },
});
