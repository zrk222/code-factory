import { describe, expect, test } from "vitest";
import { api, internal } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";

async function activeRuntime() {
  const t = authenticatedTest();
  const seed = await t.mutation(api.seed.ensureDemo, {});
  if (!seed.agentSpecId) throw new Error("missing spec");
  const blueprint = await t.mutation(api.blueprints.save, { agentSpecId: seed.agentSpecId, templateId: "outcome-generator", name: "Outcome Generator", mode: "guided", triggerKind: "manual", triggerLabel: "User starts", steps: [{ id: "generate", label: "Generate artifact", kind: "reason", humanGate: false }, { id: "approve", label: "User approves export", kind: "validate", humanGate: true }], memoryPolicy: "run-only", modelPolicy: "balanced", authorityPolicy: "approval-required", evidenceLevel: "essential", hardBudgetCents: 300 });
  const build = await t.mutation(api.credits.reserveBlueprint, { blueprintId: blueprint.blueprintId, idempotencyKey: "activate-outcome" });
  await t.mutation(api.credits.settle, { reservationId: build.reservationId, actualCredits: build.quotedCredits });
  await t.mutation(api.blueprints.activate, { blueprintId: blueprint.blueprintId, creditReservationId: build.reservationId });
  await t.mutation(api.inferenceBindings.bind, { agentSpecId: seed.agentSpecId, mode: "inherit-workspace", providerProfile: "balanced" });
  return { t, ...seed, blueprintId: blueprint.blueprintId };
}

describe("hosted execution runtime", () => {
  test("requires Agent Oven, renews its lease, and reconciles a successful worker result", async () => {
    const { t, blueprintId, workspaceId } = await activeRuntime();
    const queued = await t.mutation(api.execution.enqueue, { blueprintId, idempotencyKey: "job-1", inputRef: "object://inputs/job-1.json", inputDigest: "abc123", maxAttempts: 3 });
    expect(queued).toMatchObject({ marker: "HOSTED_EXECUTION_ENQUEUED", dependencyMarker: "AGENT_OVEN_RUNTIME_REQUIRED" });
    if (queued.quotedRuntimeCredits === undefined) throw new Error("expected a new runtime quote");
    const claimed = await t.mutation(internal.execution.claim, { jobId: queued.jobId, workerId: "worker-a" });
    expect(claimed).toMatchObject({ marker: "EXECUTION_CLAIMED", inputDigest: "abc123" });
    expect((await t.mutation(internal.execution.heartbeat, { jobId: queued.jobId, workerId: "worker-a" })).cancellationRequested).toBe(false);
    const completed = await t.mutation(internal.execution.complete, { jobId: queued.jobId, workerId: "worker-a", resultDigest: "result456", actualPlatformCredits: queued.quotedRuntimeCredits - 2 });
    expect(completed).toMatchObject({ marker: "HOSTED_EXECUTION_COMPLETED", resultDigest: "result456", releasedCredits: 2 });
    expect((await t.query(api.execution.status, { jobId: queued.jobId })).job.status).toBe("succeeded");
    const credits = await t.query(api.credits.status, { workspaceId });
    expect(credits.account?.reservedCredits).toBe(0);
  });

  test("retries once and releases all runtime credits on queued cancellation", async () => {
    const { t, blueprintId } = await activeRuntime();
    const queued = await t.mutation(api.execution.enqueue, { blueprintId, idempotencyKey: "job-retry", inputRef: "object://inputs/retry.json", inputDigest: "retry123", maxAttempts: 2 });
    await t.mutation(internal.execution.claim, { jobId: queued.jobId, workerId: "worker-a" });
    expect((await t.mutation(internal.execution.fail, { jobId: queued.jobId, workerId: "worker-a", failureCode: "E_PROVIDER_TRANSIENT", retryable: true })).marker).toBe("EXECUTION_REQUEUED");
    const canceled = await t.mutation(api.execution.cancel, { jobId: queued.jobId });
    expect(canceled).toMatchObject({ marker: "QUEUED_EXECUTION_CANCELED", creditsReleased: queued.quotedRuntimeCredits });
  });

  test("rejects credentials embedded in an input reference before reserving credits", async () => {
    const { t, blueprintId } = await activeRuntime();
    await expect(t.mutation(api.execution.enqueue, { blueprintId, idempotencyKey: "unsafe", inputRef: "https://user:password@example.com/input", inputDigest: "unsafe", maxAttempts: 1 })).rejects.toThrow("E_INPUT_REF_CREDENTIAL_FORBIDDEN");
  });
});
