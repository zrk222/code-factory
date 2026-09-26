import { v } from "convex/values";
import type { Doc, Id } from "./_generated/dataModel";
import type { MutationCtx } from "./_generated/server";
import { internalMutation, mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";
import { assertIntegerRange, assertText, receiptFingerprint } from "./domain";
import { consumeAdmission } from "./enterpriseSecurity";
import { enforceAuthoritativeSourceAdmission } from "./sourceAdmission";

const LEASE_MS = 5 * 60 * 1000;

function runtimeCredits(blueprint: Doc<"agentBlueprints">) {
  return 12 + blueprint.steps.length * 3 + (blueprint.memoryPolicy === "governed" ? 8 : blueprint.memoryPolicy === "run-only" ? 3 : 0) + (blueprint.evidenceLevel === "full" ? 5 : 0);
}

async function accountFor(ctx: MutationCtx, workspaceId: Id<"workspaces">) {
  const account = await ctx.db.query("creditAccounts").withIndex("by_workspace", (q) => q.eq("workspaceId", workspaceId)).unique();
  if (!account || account.status !== "active") throw new Error("E_CREDIT_ACCOUNT_INACTIVE");
  return account;
}

async function releaseRuntimeCredits(ctx: MutationCtx, job: Doc<"executionJobs">, reservation: Doc<"creditReservations">, now: number) {
  const account = await accountFor(ctx, job.workspaceId);
  const availableCredits = account.availableCredits + reservation.quotedCredits;
  const reservedCredits = account.reservedCredits - reservation.quotedCredits;
  await ctx.db.patch(account._id, { availableCredits, reservedCredits, updatedAt: now });
  await ctx.db.patch(reservation._id, { state: "released", actualCredits: 0, completedAt: now });
  await ctx.db.insert("creditTransactions", { workspaceId: job.workspaceId, reservationId: reservation._id, kind: "release", credits: reservation.quotedCredits, availableAfter: availableCredits, reservedAfter: reservedCredits, reference: reservation.idempotencyKey, createdAt: now });
}

/** Enqueues one digest-bound hosted job after entitlement, binding, blueprint, and credit checks. */
export const enqueue = mutation({
  args: { blueprintId: v.id("agentBlueprints"), idempotencyKey: v.string(), inputRef: v.string(), inputDigest: v.string(), maxAttempts: v.number(), runtimeAdapterId: v.optional(v.id("runtimeAdapters")) },
  handler: async (ctx, args) => {
    const blueprint = await ctx.db.get(args.blueprintId);
    if (!blueprint) throw new Error("E_BLUEPRINT_NOT_FOUND");
    await requireWorkspaceRole(ctx, blueprint.workspaceId, "operator");
    if (blueprint.status !== "active") throw new Error("E_BLUEPRINT_NOT_ACTIVE");
    const binding = await ctx.db.query("inferenceBindings").withIndex("by_agent", (q) => q.eq("agentSpecId", blueprint.agentSpecId)).unique();
    if (!binding || binding.status !== "ready") throw new Error("E_INFERENCE_BINDING_NOT_READY");
    const idempotencyKey = assertText(args.idempotencyKey, "idempotency_key", 120);
    const existing = await ctx.db.query("executionJobs").withIndex("by_workspace_key", (q) => q.eq("workspaceId", blueprint.workspaceId).eq("idempotencyKey", idempotencyKey)).unique();
    if (existing) return { marker: "EXECUTION_JOB_REPLAYED" as const, jobId: existing._id, status: existing.status };
    await enforceAuthoritativeSourceAdmission(ctx, blueprint.agentSpecId, Date.now());
    await consumeAdmission(ctx, blueprint.workspaceId, "execution.enqueue");
    const inputRef = assertText(args.inputRef, "input_ref", 500);
    if (/\/\/[^/\s]+:[^/@\s]+@/i.test(inputRef) || /[?&](?:token|key|secret|password)=/i.test(inputRef)) throw new Error("E_INPUT_REF_CREDENTIAL_FORBIDDEN");
    const inputDigest = assertText(args.inputDigest, "input_digest", 120);
    assertIntegerRange(args.maxAttempts, "max_attempts", 1, 5);
    const quote = runtimeCredits(blueprint);
    const runtimePreset = await ctx.db.query("governedRuntimePresets").withIndex("by_agent", (q) => q.eq("agentSpecId", blueprint.agentSpecId)).unique();
    if (runtimePreset && runtimePreset.status !== "published") throw new Error("E_RUNTIME_PRESET_NOT_PUBLISHED");
    const configuredAdapters = await ctx.db.query("runtimeAdapters").withIndex("by_agent", (q) => q.eq("agentSpecId", blueprint.agentSpecId)).collect();
    const runtimeAdapter = args.runtimeAdapterId ? configuredAdapters.find((item) => item._id === args.runtimeAdapterId) : configuredAdapters.find((item) => item.status === "ready");
    if (args.runtimeAdapterId && !runtimeAdapter) throw new Error("E_RUNTIME_ADAPTER_NOT_FOUND");
    if (runtimeAdapter && runtimeAdapter.status !== "ready") throw new Error("E_RUNTIME_ADAPTER_NOT_READY");
    const account = await accountFor(ctx, blueprint.workspaceId);
    if (account.availableCredits < quote) throw new Error("E_INSUFFICIENT_CREDITS");
    const now = Date.now();
    const availableCredits = account.availableCredits - quote;
    const reservedCredits = account.reservedCredits + quote;
    const jobId = await ctx.db.insert("executionJobs", { workspaceId: blueprint.workspaceId, agentSpecId: blueprint.agentSpecId, blueprintId: blueprint._id, blueprintVersion: blueprint.version, runtimePresetVersion: runtimePreset?.version, runtimePresetDigest: runtimePreset?.digest, runtimeAdapterId: runtimeAdapter?._id, runtimeEngine: runtimeAdapter?.engine, runtimeAdapterDigest: runtimeAdapter?.configDigest, idempotencyKey, inputRef, inputDigest, status: "queued", quotedRuntimeCredits: quote, maxAttempts: args.maxAttempts, attemptCount: 0, cancellationRequested: false, createdAt: now });
    const reservationId = await ctx.db.insert("creditReservations", { workspaceId: blueprint.workspaceId, agentSpecId: blueprint.agentSpecId, blueprintId: blueprint._id, idempotencyKey: `runtime:${idempotencyKey}`, quotedCredits: quote, state: "reserved", createdAt: now });
    await ctx.db.patch(jobId, { creditReservationId: reservationId });
    await ctx.db.patch(account._id, { availableCredits, reservedCredits, updatedAt: now });
    await ctx.db.insert("creditTransactions", { workspaceId: blueprint.workspaceId, reservationId, kind: "reserve", credits: quote, availableAfter: availableCredits, reservedAfter: reservedCredits, reference: `runtime:${idempotencyKey}`, createdAt: now });
    await ctx.db.insert("runtimeLeases", { workspaceId: blueprint.workspaceId, executionJobId: jobId, blueprintId: blueprint._id, blueprintVersion: blueprint.version, inputDigest, state: "active", expiresAt: now + LEASE_MS, createdAt: now });
    if (runtimePreset?.requireClarification) await ctx.db.insert("runtimeClarifications", { workspaceId: blueprint.workspaceId, executionJobId: jobId, questionId: "confirm-outcome", question: "Confirm the intended outcome and success criteria for this run.", required: true, createdAt: now });
    return { marker: "HOSTED_EXECUTION_ENQUEUED" as const, dependencyMarker: "AGENT_OVEN_RUNTIME_REQUIRED" as const, adapterMarker: runtimeAdapter ? "RUNTIME_ADAPTER_PINNED" as const : "AGENT_OVEN_NATIVE_JOB" as const, jobId, quotedRuntimeCredits: quote, runtimeEngine: runtimeAdapter?.engine };
  },
});

/** Requests cooperative cancellation and releases queued work immediately. */
export const cancel = mutation({
  args: { jobId: v.id("executionJobs") },
  handler: async (ctx, args) => {
    const job = await ctx.db.get(args.jobId);
    if (!job) throw new Error("E_EXECUTION_JOB_NOT_FOUND");
    await requireWorkspaceRole(ctx, job.workspaceId, "operator");
    if (["succeeded", "failed", "canceled"].includes(job.status)) throw new Error("E_EXECUTION_JOB_TERMINAL");
    const now = Date.now();
    if (job.status === "queued" || job.status === "suspended") {
      if (!job.creditReservationId) throw new Error("E_RUNTIME_RESERVATION_MISSING");
      const reservation = await ctx.db.get(job.creditReservationId);
      if (!reservation || reservation.state !== "reserved") throw new Error("E_RUNTIME_RESERVATION_MISSING");
      await releaseRuntimeCredits(ctx, job, reservation, now);
      await ctx.db.patch(job._id, { status: "canceled", cancellationRequested: true, completedAt: now });
      const lease = await ctx.db.query("runtimeLeases").withIndex("by_job", (q) => q.eq("executionJobId", job._id)).unique();
      if (lease) await ctx.db.patch(lease._id, { state: "revoked" });
      return { marker: "QUEUED_EXECUTION_CANCELED" as const, creditsReleased: reservation.quotedCredits };
    }
    await ctx.db.patch(job._id, { cancellationRequested: true });
    return { marker: "RUNNING_EXECUTION_CANCELLATION_REQUESTED" as const, creditsReleased: 0 };
  },
});

/** Returns the authorized job, lease state, and attempt history without provider payloads. */
export const status = query({
  args: { jobId: v.id("executionJobs") },
  handler: async (ctx, args) => {
    const job = await ctx.db.get(args.jobId);
    if (!job) throw new Error("E_EXECUTION_JOB_NOT_FOUND");
    await requireWorkspaceRole(ctx, job.workspaceId, "viewer");
    const lease = await ctx.db.query("runtimeLeases").withIndex("by_job", (q) => q.eq("executionJobId", job._id)).unique();
    const attempts = await ctx.db.query("executionAttempts").withIndex("by_job_attempt", (q) => q.eq("executionJobId", job._id)).collect();
    return { marker: "HOSTED_EXECUTION_EXPLAINED" as const, job, lease, attempts };
  },
});

/** Claims queued work from the trusted worker plane and binds the runtime lease. */
export const claim = internalMutation({
  args: { jobId: v.id("executionJobs"), workerId: v.string() },
  handler: async (ctx, args) => {
    const workerId = assertText(args.workerId, "worker_id", 120);
    const job = await ctx.db.get(args.jobId);
    if (!job || job.status !== "queued") throw new Error("E_EXECUTION_NOT_CLAIMABLE");
    const lease = await ctx.db.query("runtimeLeases").withIndex("by_job", (q) => q.eq("executionJobId", job._id)).unique();
    const now = Date.now();
    if (!lease || lease.state !== "active" || lease.expiresAt <= now) throw new Error("E_RUNTIME_LEASE_INVALID");
    const pendingClarifications = await ctx.db.query("runtimeClarifications").withIndex("by_job_question", (q) => q.eq("executionJobId", job._id)).collect();
    if (pendingClarifications.some((item) => item.required && item.answer === undefined)) throw new Error("E_CLARIFICATION_REQUIRED");
    if (job.attemptCount >= job.maxAttempts) throw new Error("E_EXECUTION_ATTEMPTS_EXHAUSTED");
    let dispatch: { schema: "agent-oven.dispatch.v1"; dispatchDigest: string; jobId: string; idempotencyKey: string; engine: NonNullable<typeof job.runtimeEngine>; targetId: string; blueprintId: string; blueprintVersion: number; inputRef: string; inputDigest: string; runtimePresetDigest?: string; adapterConfigDigest: string } | undefined;
    let endpointRef: string | undefined;
    let secretRef: string | undefined;
    if (job.runtimeAdapterId) {
      const adapter = await ctx.db.get(job.runtimeAdapterId);
      if (!adapter || adapter.status !== "ready") throw new Error("E_RUNTIME_ADAPTER_NOT_READY");
      if (!job.runtimeAdapterDigest || adapter.configDigest !== job.runtimeAdapterDigest || adapter.engine !== job.runtimeEngine) throw new Error("E_RUNTIME_ADAPTER_DIGEST_MISMATCH");
      const dispatchDigest = receiptFingerprint([String(job._id), job.idempotencyKey, adapter.configDigest, job.inputDigest, String(job.blueprintVersion), job.runtimePresetDigest ?? "none"]);
      const existingDispatch = await ctx.db.query("runtimeDispatches").withIndex("by_job", (q) => q.eq("executionJobId", job._id)).unique();
      if (existingDispatch && existingDispatch.dispatchDigest !== dispatchDigest) throw new Error("E_RUNTIME_DISPATCH_DIGEST_MISMATCH");
      if (!existingDispatch) await ctx.db.insert("runtimeDispatches", { workspaceId: job.workspaceId, executionJobId: job._id, runtimeAdapterId: adapter._id, schemaVersion: "agent-oven.dispatch.v1", transport: adapter.transport, dispatchDigest, status: "prepared", createdAt: now });
      dispatch = { schema: "agent-oven.dispatch.v1", dispatchDigest, jobId: String(job._id), idempotencyKey: job.idempotencyKey, engine: adapter.engine, targetId: adapter.targetId, blueprintId: String(job.blueprintId), blueprintVersion: job.blueprintVersion, inputRef: job.inputRef, inputDigest: job.inputDigest, runtimePresetDigest: job.runtimePresetDigest, adapterConfigDigest: adapter.configDigest };
      endpointRef = adapter.endpointRef;
      secretRef = adapter.secretRef;
    }
    const attempt = job.attemptCount + 1;
    await ctx.db.patch(job._id, { status: "running", attemptCount: attempt, startedAt: job.startedAt ?? now });
    await ctx.db.patch(lease._id, { workerId, lastHeartbeatAt: now, expiresAt: now + LEASE_MS });
    const attemptId = await ctx.db.insert("executionAttempts", { workspaceId: job.workspaceId, executionJobId: job._id, attempt, workerId, status: "running", startedAt: now });
    return { marker: "EXECUTION_CLAIMED" as const, dispatchMarker: dispatch ? "RUNTIME_DISPATCH_PREPARED" as const : undefined, jobId: job._id, attemptId, blueprintId: job.blueprintId, blueprintVersion: job.blueprintVersion, inputRef: job.inputRef, inputDigest: job.inputDigest, cancellationRequested: job.cancellationRequested, dispatch, endpointRef, secretRef };
  },
});

/** Renews a live lease and reports cooperative cancellation to the worker. */
export const heartbeat = internalMutation({
  args: { jobId: v.id("executionJobs"), workerId: v.string() },
  handler: async (ctx, args) => {
    const job = await ctx.db.get(args.jobId);
    const lease = job ? await ctx.db.query("runtimeLeases").withIndex("by_job", (q) => q.eq("executionJobId", job._id)).unique() : null;
    if (!job || job.status !== "running" || !lease || lease.state !== "active" || lease.workerId !== args.workerId) throw new Error("E_RUNTIME_LEASE_INVALID");
    const now = Date.now();
    await ctx.db.patch(lease._id, { lastHeartbeatAt: now, expiresAt: now + LEASE_MS });
    return { marker: "RUNTIME_LEASE_RENEWED" as const, cancellationRequested: job.cancellationRequested, expiresAt: now + LEASE_MS };
  },
});

/** Completes one claimed job, reconciles credits, and seals a result receipt. */
export const complete = internalMutation({
  args: { jobId: v.id("executionJobs"), workerId: v.string(), resultDigest: v.string(), actualPlatformCredits: v.number(), externalRunId: v.optional(v.string()) },
  handler: async (ctx, args) => {
    const job = await ctx.db.get(args.jobId);
    if (!job || job.status !== "running" || job.cancellationRequested) throw new Error("E_EXECUTION_NOT_COMPLETABLE");
    const lease = await ctx.db.query("runtimeLeases").withIndex("by_job", (q) => q.eq("executionJobId", job._id)).unique();
    if (!lease || lease.state !== "active" || lease.workerId !== args.workerId || lease.expiresAt <= Date.now()) throw new Error("E_RUNTIME_LEASE_INVALID");
    if (!job.creditReservationId) throw new Error("E_RUNTIME_RESERVATION_MISSING");
    const reservation = await ctx.db.get(job.creditReservationId);
    if (!reservation || reservation.state !== "reserved") throw new Error("E_RUNTIME_RESERVATION_MISSING");
    assertIntegerRange(args.actualPlatformCredits, "actual_platform_credits", 0, reservation.quotedCredits);
    const resultDigest = assertText(args.resultDigest, "result_digest", 120);
    const dispatch = await ctx.db.query("runtimeDispatches").withIndex("by_job", (q) => q.eq("executionJobId", job._id)).unique();
    const externalRunId = args.externalRunId ? assertText(args.externalRunId, "external_run_id", 160) : undefined;
    if (dispatch && !externalRunId) throw new Error("E_RUNTIME_EXTERNAL_RUN_ID_REQUIRED");
    const account = await accountFor(ctx, job.workspaceId);
    const now = Date.now();
    const released = reservation.quotedCredits - args.actualPlatformCredits;
    const availableCredits = account.availableCredits + released;
    const reservedCredits = account.reservedCredits - reservation.quotedCredits;
    await ctx.db.patch(account._id, { availableCredits, reservedCredits, spentCredits: account.spentCredits + args.actualPlatformCredits, updatedAt: now });
    await ctx.db.patch(reservation._id, { state: "settled", actualCredits: args.actualPlatformCredits, completedAt: now });
    await ctx.db.patch(job._id, { status: "succeeded", resultDigest, completedAt: now });
    await ctx.db.patch(lease._id, { state: "consumed", lastHeartbeatAt: now });
    const attempt = await ctx.db.query("executionAttempts").withIndex("by_job_attempt", (q) => q.eq("executionJobId", job._id).eq("attempt", job.attemptCount)).unique();
    if (attempt) await ctx.db.patch(attempt._id, { status: "succeeded", completedAt: now });
    if (dispatch && externalRunId) await ctx.db.patch(dispatch._id, { status: "completed", externalRunId, resultDigest, completedAt: now });
    await ctx.db.insert("creditTransactions", { workspaceId: job.workspaceId, reservationId: reservation._id, kind: "settle", credits: args.actualPlatformCredits, availableAfter: availableCredits, reservedAfter: reservedCredits, reference: reservation.idempotencyKey, createdAt: now });
    const previous = await ctx.db.query("receipts").withIndex("by_workspace_created", (q) => q.eq("workspaceId", job.workspaceId)).order("desc").first();
    const fingerprint = receiptFingerprint([String(job._id), job.inputDigest, resultDigest, String(job.blueprintVersion), String(now)]);
    await ctx.db.insert("receipts", { workspaceId: job.workspaceId, agentSpecId: job.agentSpecId, type: "platform-credit", event: "execution.succeeded", fingerprint, previousFingerprint: previous?.fingerprint, signatureState: "unsigned", createdAt: now });
    return { marker: "HOSTED_EXECUTION_COMPLETED" as const, resultDigest, actualPlatformCredits: args.actualPlatformCredits, releasedCredits: released, fingerprint };
  },
});

/** Records a bounded worker failure and either requeues or releases the reservation terminally. */
export const fail = internalMutation({
  args: { jobId: v.id("executionJobs"), workerId: v.string(), failureCode: v.string(), retryable: v.boolean() },
  handler: async (ctx, args) => {
    const job = await ctx.db.get(args.jobId);
    if (!job || job.status !== "running") throw new Error("E_EXECUTION_NOT_RUNNING");
    const lease = await ctx.db.query("runtimeLeases").withIndex("by_job", (q) => q.eq("executionJobId", job._id)).unique();
    if (!lease || lease.workerId !== args.workerId) throw new Error("E_RUNTIME_LEASE_INVALID");
    const failureCode = assertText(args.failureCode, "failure_code", 120);
    const now = Date.now();
    const attempt = await ctx.db.query("executionAttempts").withIndex("by_job_attempt", (q) => q.eq("executionJobId", job._id).eq("attempt", job.attemptCount)).unique();
    const willRetry = args.retryable && !job.cancellationRequested && job.attemptCount < job.maxAttempts;
    if (attempt) await ctx.db.patch(attempt._id, { status: willRetry ? "retryable-failure" : "terminal-failure", failureCode, completedAt: now });
    if (willRetry) {
      await ctx.db.patch(job._id, { status: "queued", failureCode });
      await ctx.db.patch(lease._id, { workerId: undefined, lastHeartbeatAt: now, expiresAt: now + LEASE_MS });
      return { marker: "EXECUTION_REQUEUED" as const, nextAttempt: job.attemptCount + 1 };
    }
    const dispatch = await ctx.db.query("runtimeDispatches").withIndex("by_job", (q) => q.eq("executionJobId", job._id)).unique();
    if (dispatch) await ctx.db.patch(dispatch._id, { status: "failed", failureCode, completedAt: now });
    if (!job.creditReservationId) throw new Error("E_RUNTIME_RESERVATION_MISSING");
    const reservation = await ctx.db.get(job.creditReservationId);
    if (!reservation || reservation.state !== "reserved") throw new Error("E_RUNTIME_RESERVATION_MISSING");
    await releaseRuntimeCredits(ctx, job, reservation, now);
    await ctx.db.patch(job._id, { status: job.cancellationRequested ? "canceled" : "failed", failureCode, completedAt: now });
    await ctx.db.patch(lease._id, { state: "revoked", lastHeartbeatAt: now });
    return { marker: "EXECUTION_TERMINATED" as const, status: job.cancellationRequested ? "canceled" as const : "failed" as const, creditsReleased: reservation.quotedCredits };
  },
});
