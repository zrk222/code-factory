import { v } from "convex/values";
import { internalMutation, mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";
import { assertIntegerRange, assertText, receiptFingerprint } from "./domain";
import { evaluateRecipeEligibility, generateRecipeCandidates, selectRecipeChampion } from "./recipeLabDomain";

const memoryMode = v.union(v.literal("none"), v.literal("run-only"), v.literal("governed"));
const authorityMode = v.union(v.literal("read-only"), v.literal("propose"), v.literal("approval-required"));

function opaqueRef(value: string) {
  const ref = assertText(value, "evaluation_set_ref", 500);
  if (/\/\/[^/\s]+:[^/@\s]+@/i.test(ref) || /[?&](?:token|key|secret|password)=/i.test(ref)) throw new Error("E_RECIPE_SENSITIVE_REF");
  return ref;
}

function validateStudyNumbers(args: { trialCount: number; studyCredits: number; trialCredits: number; graceCheckpointCount: number; pruneFloor: number; minQuality: number; maxLatencyMs: number; qualityWeight: number; costWeight: number; latencyWeight: number }) {
  assertIntegerRange(args.trialCount, "trial_count", 2, 24);
  assertIntegerRange(args.studyCredits, "study_credits", 1, 100000);
  assertIntegerRange(args.trialCredits, "trial_credits", 1, Math.min(10000, args.studyCredits));
  assertIntegerRange(args.graceCheckpointCount, "grace_checkpoint_count", 1, 5);
  assertIntegerRange(args.pruneFloor, "prune_floor", 0, 100);
  assertIntegerRange(args.minQuality, "minimum_quality", 0, 100);
  assertIntegerRange(args.maxLatencyMs, "maximum_latency_ms", 1, 86400000);
  if (args.qualityWeight + args.costWeight + args.latencyWeight !== 100 || [args.qualityWeight, args.costWeight, args.latencyWeight].some((weight) => !Number.isInteger(weight) || weight < 0 || weight > 100)) throw new Error("E_RECIPE_WEIGHTS_INVALID");
}

/** Creates one bounded, human-owned recipe optimization study. */
export const createStudy = mutation({
  args: {
    agentSpecId: v.id("agentSpecs"), name: v.string(), useCase: v.string(), evaluationSetRef: v.string(), evaluationSetDigest: v.string(),
    trialCount: v.number(), studyCredits: v.number(), trialCredits: v.number(), graceCheckpointCount: v.number(), pruneFloor: v.number(),
    minQuality: v.number(), maxLatencyMs: v.number(), qualityWeight: v.number(), costWeight: v.number(), latencyWeight: v.number(),
    modelCandidates: v.array(v.string()), retrievalCandidates: v.array(v.number()), memoryCandidates: v.array(memoryMode), authorityCandidates: v.array(authorityMode),
  },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    const authorized = await requireWorkspaceRole(ctx, spec.workspaceId, "operator");
    validateStudyNumbers(args);
    generateRecipeCandidates({ trialCount: args.trialCount, models: args.modelCandidates, retrievalTopK: args.retrievalCandidates, memoryModes: args.memoryCandidates, authorityModes: args.authorityCandidates });
    const studyId = await ctx.db.insert("recipeStudies", {
      workspaceId: spec.workspaceId, agentSpecId: spec._id, name: assertText(args.name, "recipe_study_name", 120), useCase: assertText(args.useCase, "recipe_use_case", 500),
      evaluationSetRef: opaqueRef(args.evaluationSetRef), evaluationSetDigest: assertText(args.evaluationSetDigest, "evaluation_set_digest", 120),
      trialCount: args.trialCount, studyCredits: args.studyCredits, trialCredits: args.trialCredits, spentCredits: 0,
      graceCheckpointCount: args.graceCheckpointCount, pruneFloor: args.pruneFloor, minQuality: args.minQuality, maxLatencyMs: args.maxLatencyMs,
      qualityWeight: args.qualityWeight, costWeight: args.costWeight, latencyWeight: args.latencyWeight,
      modelCandidates: args.modelCandidates.map((item) => assertText(item, "recipe_model", 160)), retrievalCandidates: args.retrievalCandidates,
      memoryCandidates: args.memoryCandidates, authorityCandidates: args.authorityCandidates, status: "draft", creatorId: authorized.tokenIdentifier, createdAt: Date.now(),
    });
    return { marker: "AGENT_RECIPE_STUDY_CREATED" as const, studyId, status: "draft" as const };
  },
});

/** Materializes deterministic candidate records; no provider or model is called. */
export const startStudy = mutation({
  args: { studyId: v.id("recipeStudies") },
  handler: async (ctx, args) => {
    const study = await ctx.db.get(args.studyId);
    if (!study) throw new Error("E_RECIPE_STUDY_NOT_FOUND");
    await requireWorkspaceRole(ctx, study.workspaceId, "operator");
    if (study.status !== "draft") throw new Error("E_RECIPE_STUDY_NOT_DRAFT");
    const candidates = generateRecipeCandidates({ trialCount: study.trialCount, models: study.modelCandidates, retrievalTopK: study.retrievalCandidates, memoryModes: study.memoryCandidates, authorityModes: study.authorityCandidates });
    const createdAt = Date.now();
    for (const [index, candidate] of candidates.entries()) {
      const canonical = JSON.stringify(candidate);
      await ctx.db.insert("recipeTrials", { workspaceId: study.workspaceId, agentSpecId: study.agentSpecId, studyId: study._id, trialNumber: index + 1, ...candidate, recipeDigest: receiptFingerprint([String(study._id), canonical]), state: "queued", createdAt });
    }
    await ctx.db.patch(study._id, { status: "running", startedAt: createdAt });
    return { marker: "RECIPE_STUDY_STARTED" as const, evidenceMarker: "RECIPE_CANDIDATES_GENERATED" as const, studyId: study._id, candidateCount: candidates.length, modelCalls: 0 };
  },
});

/** Proposes the Pareto-frontier champion after every trial reaches a terminal state. */
export const finalizeStudy = mutation({
  args: { studyId: v.id("recipeStudies") },
  handler: async (ctx, args) => {
    const study = await ctx.db.get(args.studyId);
    if (!study) throw new Error("E_RECIPE_STUDY_NOT_FOUND");
    await requireWorkspaceRole(ctx, study.workspaceId, "operator");
    if (study.status !== "running") throw new Error("E_RECIPE_STUDY_NOT_RUNNING");
    const trials = await ctx.db.query("recipeTrials").withIndex("by_study_number", (q) => q.eq("studyId", study._id)).collect();
    if (trials.some((trial) => trial.state === "queued" || trial.state === "running")) throw new Error("E_RECIPE_TRIALS_INCOMPLETE");
    const metrics = trials.filter((trial) => trial.state === "completed" && trial.qualityScore !== undefined && trial.costCredits !== undefined && trial.latencyMs !== undefined && trial.policyViolations !== undefined).map((trial) => ({ recipeDigest: trial.recipeDigest, qualityScore: trial.qualityScore!, costCredits: trial.costCredits!, latencyMs: trial.latencyMs!, policyViolations: trial.policyViolations! }));
    const result = selectRecipeChampion(metrics, { minQuality: study.minQuality, maxLatencyMs: study.maxLatencyMs, perTrialCreditCap: study.trialCredits }, { quality: study.qualityWeight, cost: study.costWeight, latency: study.latencyWeight });
    if (!result.champion) {
      await ctx.db.patch(study._id, { status: "review", finalizedAt: Date.now(), frontierDigests: [] });
      return { marker: "RECIPE_STUDY_NO_CHAMPION" as const, reasonCode: "E_RECIPE_NO_ELIGIBLE_CHAMPION" as const, studyId: study._id };
    }
    const champion = trials.find((trial) => trial.recipeDigest === result.champion!.recipeDigest)!;
    const now = Date.now();
    await ctx.db.patch(study._id, { status: "review", championTrialId: champion._id, championDigest: champion.recipeDigest, frontierDigests: result.frontier.map((item) => item.recipeDigest), finalizedAt: now });
    await ctx.db.insert("recipePromotions", { workspaceId: study.workspaceId, agentSpecId: study.agentSpecId, studyId: study._id, trialId: champion._id, recipeDigest: champion.recipeDigest, status: "pending", requestedBy: study.creatorId, createdAt: now });
    return { marker: "RECIPE_CHAMPION_PROPOSED" as const, studyId: study._id, trialId: champion._id, recipeDigest: champion.recipeDigest, frontierSize: result.frontier.length, weightedScore: result.weightedScore };
  },
});

/** Records independent approval without activating, deploying, or publishing the recipe. */
export const approveChampion = mutation({
  args: { studyId: v.id("recipeStudies"), expectedRecipeDigest: v.string() },
  handler: async (ctx, args) => {
    const study = await ctx.db.get(args.studyId);
    if (!study) throw new Error("E_RECIPE_STUDY_NOT_FOUND");
    const authorized = await requireWorkspaceRole(ctx, study.workspaceId, "reviewer");
    if (!(["owner", "admin", "reviewer"] as string[]).includes(authorized.membership.role)) throw new Error("E_ROLE_FORBIDDEN");
    if (authorized.tokenIdentifier === study.creatorId) throw new Error("E_RECIPE_SELF_APPROVAL_FORBIDDEN");
    if (study.status !== "review" || !study.championDigest || study.championDigest !== args.expectedRecipeDigest) throw new Error("E_RECIPE_CHAMPION_DIGEST_MISMATCH");
    const promotion = await ctx.db.query("recipePromotions").withIndex("by_study", (q) => q.eq("studyId", study._id)).unique();
    if (!promotion || promotion.status !== "pending") throw new Error("E_RECIPE_PROMOTION_NOT_PENDING");
    const now = Date.now();
    await ctx.db.patch(promotion._id, { status: "approved", approvedBy: authorized.tokenIdentifier, decidedAt: now });
    await ctx.db.patch(study._id, { status: "approved", approvedAt: now });
    return { marker: "RECIPE_CHAMPION_APPROVED" as const, studyId: study._id, recipeDigest: study.championDigest, activationState: "human-controlled" as const };
  },
});

/** Returns the latest study without object references or actor and worker identities. */
export const getStudy = query({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "viewer");
    const study = await ctx.db.query("recipeStudies").withIndex("by_agent_created", (q) => q.eq("agentSpecId", spec._id)).order("desc").first();
    if (!study) return null;
    const [trials, promotion] = await Promise.all([
      ctx.db.query("recipeTrials").withIndex("by_study_number", (q) => q.eq("studyId", study._id)).collect(),
      ctx.db.query("recipePromotions").withIndex("by_study", (q) => q.eq("studyId", study._id)).unique(),
    ]);
    const { evaluationSetRef: _evaluationSetRef, creatorId: _creatorId, ...safeStudy } = study;
    return { marker: "RECIPE_STUDY_REDACTED" as const, study: safeStudy, trials: trials.map(({ claimedBy: _claimedBy, ...trial }) => trial), promotion: promotion ? { status: promotion.status, recipeDigest: promotion.recipeDigest, createdAt: promotion.createdAt, decidedAt: promotion.decidedAt } : null };
  },
});

/** Claims exactly one queued trial for a trusted hosted worker. */
export const claimTrial = internalMutation({
  args: { studyId: v.id("recipeStudies"), workerId: v.string() },
  handler: async (ctx, args) => {
    const study = await ctx.db.get(args.studyId);
    if (!study || study.status !== "running") throw new Error("E_RECIPE_STUDY_NOT_RUNNING");
    if (study.spentCredits >= study.studyCredits) throw new Error("E_RECIPE_STUDY_BUDGET_EXHAUSTED");
    const trial = await ctx.db.query("recipeTrials").withIndex("by_study_state", (q) => q.eq("studyId", study._id).eq("state", "queued")).first();
    if (!trial) throw new Error("E_RECIPE_NO_QUEUED_TRIAL");
    await ctx.db.patch(trial._id, { state: "running", claimedBy: assertText(args.workerId, "recipe_worker_id", 120), startedAt: Date.now() });
    return { marker: "RECIPE_TRIAL_CLAIMED" as const, trialId: trial._id, recipeDigest: trial.recipeDigest, config: { model: trial.model, retrievalTopK: trial.retrievalTopK, memoryMode: trial.memoryMode, authorityMode: trial.authorityMode }, trialCredits: study.trialCredits };
  },
});

function checkpointReason(study: { trialCredits: number; studyCredits: number; spentCredits: number; graceCheckpointCount: number; pruneFloor: number }, args: { checkpointNumber: number; qualityScore: number; cumulativeCredits: number; policyViolations: number }, previousCredits: number) {
  if (args.policyViolations > 0) return "TRIAL_POLICY_VIOLATION_PRUNED";
  if (args.cumulativeCredits > study.trialCredits) return "TRIAL_CREDIT_LIMIT_PRUNED";
  if (study.spentCredits + args.cumulativeCredits - previousCredits > study.studyCredits) return "STUDY_CREDIT_LIMIT_PRUNED";
  if (args.checkpointNumber > study.graceCheckpointCount && args.qualityScore < study.pruneFloor) return "TRIAL_QUALITY_PRUNED";
  return null;
}

/** Reserves cumulative credits and records one pruning-aware progress checkpoint. */
export const recordCheckpoint = internalMutation({
  args: { trialId: v.id("recipeTrials"), checkpointNumber: v.number(), qualityScore: v.number(), cumulativeCredits: v.number(), cumulativeLatencyMs: v.number(), policyViolations: v.number() },
  handler: async (ctx, args) => {
    const trial = await ctx.db.get(args.trialId);
    if (!trial || trial.state !== "running") throw new Error("E_RECIPE_TRIAL_NOT_RUNNING");
    const study = await ctx.db.get(trial.studyId);
    if (!study || study.status !== "running") throw new Error("E_RECIPE_STUDY_NOT_RUNNING");
    assertIntegerRange(args.checkpointNumber, "checkpoint_number", 1, 100);
    assertIntegerRange(args.qualityScore, "checkpoint_quality", 0, 100);
    assertIntegerRange(args.cumulativeCredits, "checkpoint_credits", 0, 10000);
    assertIntegerRange(args.cumulativeLatencyMs, "checkpoint_latency_ms", 0, 86400000);
    assertIntegerRange(args.policyViolations, "checkpoint_policy_violations", 0, 100);
    const previous = await ctx.db.query("recipeCheckpoints").withIndex("by_trial_checkpoint", (q) => q.eq("trialId", trial._id)).order("desc").first();
    const expectedNumber = (previous?.checkpointNumber ?? 0) + 1;
    if (args.checkpointNumber !== expectedNumber || args.cumulativeCredits < (previous?.cumulativeCredits ?? 0) || args.cumulativeLatencyMs < (previous?.cumulativeLatencyMs ?? 0)) throw new Error("E_RECIPE_CHECKPOINT_SEQUENCE");
    const previousCredits = previous?.cumulativeCredits ?? 0;
    const reason = checkpointReason(study, args, previousCredits);
    await ctx.db.insert("recipeCheckpoints", { workspaceId: trial.workspaceId, studyId: study._id, ...args, createdAt: Date.now() });
    if (reason) {
      await ctx.db.patch(trial._id, { state: "pruned", pruneReason: reason, completedAt: Date.now() });
      return { marker: "RECIPE_TRIAL_PRUNED" as const, reasonCode: reason, trialId: trial._id };
    }
    await ctx.db.patch(study._id, { spentCredits: study.spentCredits + args.cumulativeCredits - previousCredits });
    return { marker: "RECIPE_CHECKPOINT_RECORDED" as const, trialId: trial._id, checkpointNumber: args.checkpointNumber, reservedStudyCredits: study.spentCredits + args.cumulativeCredits - previousCredits };
  },
});

/** Completes a claimed trial using only pre-reserved credits and digest-bound evidence. */
export const completeTrial = internalMutation({
  args: { trialId: v.id("recipeTrials"), qualityScore: v.number(), costCredits: v.number(), latencyMs: v.number(), policyViolations: v.number(), evidenceDigest: v.string() },
  handler: async (ctx, args) => {
    const trial = await ctx.db.get(args.trialId);
    if (!trial || trial.state !== "running") throw new Error("E_RECIPE_TRIAL_NOT_RUNNING");
    const study = await ctx.db.get(trial.studyId);
    if (!study || study.status !== "running") throw new Error("E_RECIPE_STUDY_NOT_RUNNING");
    assertIntegerRange(args.qualityScore, "trial_quality", 0, 100);
    assertIntegerRange(args.costCredits, "trial_cost_credits", 1, 10000);
    assertIntegerRange(args.latencyMs, "trial_latency_ms", 0, 86400000);
    assertIntegerRange(args.policyViolations, "trial_policy_violations", 0, 100);
    const evidenceDigest = assertText(args.evidenceDigest, "trial_evidence_digest", 120);
    if (evidenceDigest.length < 16) throw new Error("E_INVALID_TRIAL_EVIDENCE_DIGEST");
    const checkpoint = await ctx.db.query("recipeCheckpoints").withIndex("by_trial_checkpoint", (q) => q.eq("trialId", trial._id)).order("desc").first();
    if (!checkpoint || args.costCredits > checkpoint.cumulativeCredits) throw new Error("E_RECIPE_CREDIT_NOT_RESERVED");
    const eligibility = evaluateRecipeEligibility({ recipeDigest: trial.recipeDigest, qualityScore: args.qualityScore, costCredits: args.costCredits, latencyMs: args.latencyMs, policyViolations: args.policyViolations }, { minQuality: study.minQuality, maxLatencyMs: study.maxLatencyMs, perTrialCreditCap: study.trialCredits });
    await ctx.db.patch(trial._id, { state: "completed", qualityScore: args.qualityScore, costCredits: args.costCredits, latencyMs: args.latencyMs, policyViolations: args.policyViolations, eligible: eligibility.eligible, evidenceDigest, completedAt: Date.now() });
    return { marker: "RECIPE_TRIAL_COMPLETED" as const, trialId: trial._id, eligible: eligibility.eligible, reasons: eligibility.reasons };
  },
});

/** Marks an unrecoverable hosted-worker failure without turning it into evidence. */
export const failTrial = internalMutation({
  args: { trialId: v.id("recipeTrials"), failureCode: v.string() },
  handler: async (ctx, args) => {
    const trial = await ctx.db.get(args.trialId);
    if (!trial || trial.state !== "running") throw new Error("E_RECIPE_TRIAL_NOT_RUNNING");
    await ctx.db.patch(trial._id, { state: "failed", pruneReason: assertText(args.failureCode, "recipe_failure_code", 120), completedAt: Date.now() });
    return { marker: "RECIPE_TRIAL_FAILED" as const, trialId: trial._id };
  },
});
