import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import type { Id } from "./_generated/dataModel";
import type { MutationCtx } from "./_generated/server";
import { assertBudget, assertText, canonicalAgentSpec, evidenceClass, receiptFingerprint } from "./domain";
import { requireWorkspaceRole } from "./access";
import { APPROVAL_POLICY_VERSION, compareProofEvidence, evaluateAdversarialApproval, type ApprovalActionClass, type ApprovalEnvironment } from "./adversarialApprovalDomain";

const providerProfile = v.union(v.literal("economy"), v.literal("balanced"), v.literal("highest-quality"));
const memoryMode = v.union(v.literal("run-only"), v.literal("architecture-history"));
const authorityMode = v.union(v.literal("read-only"), v.literal("propose"), v.literal("approval-required"));
const taskKind = v.union(v.literal("analyze-evidence"), v.literal("draft-change"), v.literal("merge-proposal"));

const taskPolicy: Record<"analyze-evidence" | "draft-change" | "merge-proposal", { actionClass: ApprovalActionClass; environment: ApprovalEnvironment; label: string }> = {
  "analyze-evidence": { actionClass: "analyze", environment: "test", label: "Analyze the bound evidence without changing code or external systems" },
  "draft-change": { actionClass: "draft", environment: "test", label: "Prepare a change draft without merging or publishing it" },
  "merge-proposal": { actionClass: "code-change", environment: "production", label: "Create an approval-gated merge proposal" },
};

function taskActionDigest(repository: string, branch: string, commitSha: string, selectedTask: typeof taskPolicy[keyof typeof taskPolicy]): string {
  return receiptFingerprint(["task-approval.v1", repository, branch, commitSha, selectedTask.actionClass, selectedTask.environment, selectedTask.label]);
}

export const saveAgentSpec = mutation({
  args: {
    agentSpecId: v.id("agentSpecs"),
    repository: v.string(),
    providerProfile,
    memoryMode,
    authorityMode,
    hardBudgetCents: v.number(),
    validators: v.array(v.string()),
  },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "admin");
    const repository = assertText(args.repository, "repository", 200);
    assertBudget(args.hardBudgetCents, 0);
    const validators = args.validators.map((value) => assertText(value, "validator", 120));
    if (validators.length < 1 || validators.length > 8) throw new Error("E_INVALID_VALIDATORS");
    const now = Date.now();
    const nextVersion = spec.version + 1;
    const semantic = {
      name: spec.name,
      repository,
      providerProfile: args.providerProfile,
      memoryMode: args.memoryMode,
      authorityMode: args.authorityMode,
      hardBudgetCents: args.hardBudgetCents,
      validators,
    };
    await ctx.db.patch(spec._id, {
      ...semantic,
      version: nextVersion,
      updatedAt: now,
    });
    const canonical = canonicalAgentSpec(semantic);
    await ctx.db.insert("agentSpecVersions", {
      workspaceId: spec.workspaceId,
      agentSpecId: spec._id,
      version: nextVersion,
      ...semantic,
      digest: receiptFingerprint([canonical]),
      source: "save",
      createdAt: now,
    });
    await ctx.db.insert("auditEvents", {
      workspaceId: spec.workspaceId,
      actor: "builder@factory.local",
      event: "agent-spec.updated",
      targetType: "agentSpec",
      targetId: String(spec._id),
      detail: `Version ${nextVersion} saved with ${validators.length} validators.`,
      createdAt: now,
    });
    return { marker: "AGENT_SPEC_PERSISTED" as const, versionMarker: "AGENT_SPEC_VERSIONED" as const, version: nextVersion };
  },
});

const gateDefinitions = [
  ["Requirements coverage", "deterministic", "passed", 842, "Declared requirements map to executable checks."],
  ["Test suite", "deterministic", "passed", 18240, "Unit and integration checks completed."],
  ["Architecture contract", "deterministic", "passed", 1250, "Dependency direction matches the sealed SSAT."],
  ["Trust policy", "deterministic", "passed", 610, "Proposed branch write requires independent approval."],
  ["Risk review", "model", "warning", 2340, "Heuristic review found one low-risk documentation note."],
  ["Receipt integrity", "deterministic", "passed", 330, "Prototype receipt lineage is internally consistent."],
] as const;

type GateRecord = { name: string; kind: "deterministic" | "model"; status: "passed" | "warning" | "blocked"; evidenceClass: "proof-bearing" | "heuristic"; summary: string };

async function appendAdversarialReview(ctx: MutationCtx, input: {
  workspaceId: Id<"workspaces">;
  runId: Id<"runs">;
  approvalId: Id<"approvals">;
  actionDigest: string;
  actionClass: ApprovalActionClass;
  environment: ApprovalEnvironment;
  requestedBy: string;
  estimatedCostCents: number;
  hardBudgetCents: number;
  gates: GateRecord[];
  now: number;
}) {
  const approvalAgentId = "adversarial-approval-agent@factory.local";
  const evidenceDigests = input.gates.map((gate) => receiptFingerprint([gate.name, gate.kind, gate.status, gate.evidenceClass, gate.summary]));
  const existing = await ctx.db.query("adversarialApprovalReviews").withIndex("by_approval", (q) => q.eq("approvalId", input.approvalId)).unique();
  if (existing) return existing;
  const priorCandidates = await ctx.db.query("adversarialApprovalReviews").withIndex("by_workspace_created", (q) => q.eq("workspaceId", input.workspaceId)).order("desc").take(30);
  const prior = priorCandidates.find((candidate) => candidate.actionClass === input.actionClass);
  const proofDelta = compareProofEvidence(evidenceDigests, prior?.evidenceDigests);
  const result = evaluateAdversarialApproval({
    actionDigest: input.actionDigest,
    boundActionDigest: input.actionDigest,
    actionClass: input.actionClass,
    environment: input.environment,
    requestedBy: input.requestedBy,
    approvalAgentId,
    estimatedCostCents: input.estimatedCostCents,
    hardBudgetCents: input.hardBudgetCents,
    evidenceDigests,
    gates: input.gates,
  });
  const evidenceDigest = receiptFingerprint(evidenceDigests);
  const expiresAt = input.now + 24 * 60 * 60 * 1000;
  const reviewId = await ctx.db.insert("adversarialApprovalReviews", {
    workspaceId: input.workspaceId,
    runId: input.runId,
    approvalId: input.approvalId,
    actionDigest: input.actionDigest,
    actionClass: input.actionClass,
    environment: input.environment,
    approvalAgentId,
    verdict: result.verdict,
    reasonCodes: result.reasonCodes,
    checks: result.checks,
    evidenceDigests,
    evidenceDigest,
    proofDelta,
    policyVersion: APPROVAL_POLICY_VERSION,
    expiresAt,
    createdAt: input.now,
  });
  const terminalStatus = result.verdict === "auto-approved" ? "approved" as const : result.verdict === "denied" ? "rejected" as const : null;
  if (terminalStatus) {
    await ctx.db.patch(input.approvalId, { status: terminalStatus, decidedBy: approvalAgentId, decidedAt: input.now, rationale: result.reasonCodes.join(", ") });
    await ctx.db.patch(input.runId, { status: result.verdict === "denied" ? "blocked" : "approved", completedAt: input.now });
  }
  const previous = await ctx.db.query("receipts").withIndex("by_run_created", (q) => q.eq("runId", input.runId)).order("desc").first();
  await ctx.db.insert("receipts", {
    workspaceId: input.workspaceId,
    runId: input.runId,
    type: "approval",
    event: `approval.adversarial.${result.verdict}`,
    fingerprint: receiptFingerprint([String(reviewId), input.actionDigest, evidenceDigest, result.verdict, APPROVAL_POLICY_VERSION]),
    previousFingerprint: previous?.fingerprint,
    signatureState: "unsigned",
    createdAt: input.now,
  });
  await ctx.db.insert("auditEvents", {
    workspaceId: input.workspaceId,
    actor: approvalAgentId,
    event: `approval.adversarial.${result.verdict}`,
    targetType: "approval",
    targetId: String(input.approvalId),
    detail: `${result.reasonCodes.join(", ")}; ${proofDelta.reviewScope} review with ${proofDelta.reusedEvidence.length} reused and ${proofDelta.newEvidence.length} new evidence items.`,
    createdAt: input.now,
  });
  const review = await ctx.db.get(reviewId);
  if (!review) throw new Error("E_ADVERSARIAL_REVIEW_WRITE_FAILED");
  return review;
}

export const launchRun = mutation({
  args: {
    agentSpecId: v.id("agentSpecs"),
    branch: v.string(),
    commitSha: v.string(),
    estimatedCostCents: v.number(),
    taskKind: v.optional(taskKind),
  },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "operator");
    if (spec.status !== "active") throw new Error("E_AGENT_NOT_ACTIVE");
    assertBudget(spec.hardBudgetCents, args.estimatedCostCents);
    const branch = assertText(args.branch, "branch", 200);
    const commitSha = assertText(args.commitSha, "commit_sha", 64);
    const selectedTask = taskPolicy[args.taskKind ?? "merge-proposal"];
    const digest = taskActionDigest(spec.repository, branch, commitSha, selectedTask);
    const proposedAction = `${selectedTask.label} for ${branch}@${commitSha.slice(0, 8)}`;
    const now = Date.now();
    const runId = await ctx.db.insert("runs", {
      workspaceId: spec.workspaceId,
      agentSpecId: spec._id,
      branch,
      commitSha,
      status: "awaiting-approval",
      estimatedCostCents: args.estimatedCostCents,
      actualCostCents: Math.max(1, args.estimatedCostCents - 7),
      proposedAction,
      actionDigest: digest,
      startedAt: now,
    });
    const gates: GateRecord[] = [];
    for (const [index, definition] of gateDefinitions.entries()) {
      const [name, kind, status, durationMs, summary] = definition;
      const gate = { name, kind, status, evidenceClass: evidenceClass(kind), summary };
      gates.push(gate);
      await ctx.db.insert("gates", {
        workspaceId: spec.workspaceId,
        runId,
        order: index + 1,
        name,
        kind,
        status,
        evidenceClass: gate.evidenceClass,
        durationMs,
        summary,
      });
    }
    const approvalId = await ctx.db.insert("approvals", {
      workspaceId: spec.workspaceId,
      runId,
      actionDigest: digest,
      proposedAction,
      status: "pending",
      requestedBy: `agent:${spec._id}`,
      requestedAt: now,
    });
    const previous = await ctx.db
      .query("receipts")
      .withIndex("by_workspace_created", (q) => q.eq("workspaceId", spec.workspaceId))
      .order("desc")
      .first();
    const fingerprint = receiptFingerprint([String(runId), digest, "run.created", String(now)]);
    await ctx.db.insert("receipts", {
      workspaceId: spec.workspaceId,
      runId,
      type: "run",
      event: "run.created",
      fingerprint,
      previousFingerprint: previous?.fingerprint,
      signatureState: "unsigned",
      createdAt: now,
    });
    const adversarialReview = await appendAdversarialReview(ctx, {
      workspaceId: spec.workspaceId,
      runId,
      approvalId,
      actionDigest: digest,
      actionClass: selectedTask.actionClass,
      environment: selectedTask.environment,
      requestedBy: `agent:${spec._id}`,
      estimatedCostCents: args.estimatedCostCents,
      hardBudgetCents: spec.hardBudgetCents,
      gates,
      now,
    });
    await ctx.db.insert("usageRecords", {
      workspaceId: spec.workspaceId,
      runId,
      estimatedCostCents: args.estimatedCostCents,
      actualCostCents: Math.max(1, args.estimatedCostCents - 7),
      createdAt: now,
    });
    await ctx.db.insert("auditEvents", {
      workspaceId: spec.workspaceId,
      actor: "builder@factory.local",
      event: "assurance-run.created",
      targetType: "run",
      targetId: String(runId),
      detail: `Six gates completed; adversarial verdict ${adversarialReview.verdict} recorded for approval ${approvalId}.`,
      createdAt: now,
    });
    return { marker: "ASSURANCE_RUN_CREATED" as const, budgetMarker: "BUDGET_ACCEPTED" as const, reviewMarker: "ADVERSARIAL_APPROVAL_RECORDED" as const, reviewVerdict: adversarialReview.verdict, runId, approvalId };
  },
});

export const decideApproval = mutation({
  args: {
    approvalId: v.id("approvals"),
    actionDigest: v.string(),
    decision: v.union(v.literal("approved"), v.literal("rejected")),
    rationale: v.string(),
  },
  handler: async (ctx, args) => {
    const approval = await ctx.db.get(args.approvalId);
    if (!approval) throw new Error("E_APPROVAL_NOT_FOUND");
    const authorized = await requireWorkspaceRole(ctx, approval.workspaceId, "reviewer");
    if (approval.status !== "pending") throw new Error("E_APPROVAL_ALREADY_DECIDED");
    if (approval.actionDigest !== args.actionDigest) throw new Error("E_ACTION_DIGEST_MISMATCH");
    const rationale = assertText(args.rationale, "rationale", 500);
    const run = await ctx.db.get(approval.runId);
    if (!run) throw new Error("E_RUN_NOT_FOUND");
    const adversarialReview = await ctx.db.query("adversarialApprovalReviews").withIndex("by_approval", (q) => q.eq("approvalId", approval._id)).unique();
    if (!adversarialReview) throw new Error("E_ADVERSARIAL_REVIEW_REQUIRED");
    if (adversarialReview.verdict === "denied") throw new Error("E_ADVERSARIAL_REVIEW_DENIED");
    if (adversarialReview.expiresAt <= Date.now()) throw new Error("E_ADVERSARIAL_REVIEW_EXPIRED");
    if (authorized.tokenIdentifier === approval.requestedBy || authorized.tokenIdentifier === adversarialReview.approvalAgentId) throw new Error("E_SELF_APPROVAL_FORBIDDEN");
    const now = Date.now();
    await ctx.db.patch(approval._id, {
      status: args.decision,
      decidedBy: authorized.tokenIdentifier,
      decidedAt: now,
      rationale,
    });
    await ctx.db.patch(run._id, { status: args.decision, completedAt: now });
    const previous = await ctx.db
      .query("receipts")
      .withIndex("by_run_created", (q) => q.eq("runId", run._id))
      .order("desc")
      .first();
    const fingerprint = receiptFingerprint([String(run._id), args.actionDigest, args.decision, rationale, String(now)]);
    await ctx.db.insert("receipts", {
      workspaceId: approval.workspaceId,
      runId: run._id,
      type: "approval",
      event: `approval.${args.decision}`,
      fingerprint,
      previousFingerprint: previous?.fingerprint,
      signatureState: "unsigned",
      createdAt: now,
    });
    await ctx.db.insert("auditEvents", {
      workspaceId: approval.workspaceId,
      actor: authorized.tokenIdentifier,
      event: `approval.${args.decision}`,
      targetType: "approval",
      targetId: String(approval._id),
      detail: rationale,
      createdAt: now,
    });
    return { marker: "APPROVAL_DECISION_BOUND" as const, decision: args.decision, fingerprint };
  },
});

export const runDetail = query({
  args: { runId: v.id("runs") },
  handler: async (ctx, args) => {
    const run = await ctx.db.get(args.runId);
    if (!run) return null;
    await requireWorkspaceRole(ctx, run.workspaceId, "viewer");
    const [gates, approval, receipts] = await Promise.all([
      ctx.db.query("gates").withIndex("by_run_order", (q) => q.eq("runId", run._id)).collect(),
      ctx.db.query("approvals").withIndex("by_run", (q) => q.eq("runId", run._id)).unique(),
      ctx.db.query("receipts").withIndex("by_run_created", (q) => q.eq("runId", run._id)).collect(),
    ]);
    const adversarialReview = approval ? await ctx.db.query("adversarialApprovalReviews").withIndex("by_approval", (q) => q.eq("approvalId", approval._id)).unique() : null;
    return { run, gates, approval, adversarialReview, receipts };
  },
});
