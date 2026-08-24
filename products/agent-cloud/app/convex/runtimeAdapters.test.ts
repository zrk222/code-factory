import { describe, expect, test } from "vitest";
import { api, internal } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";

async function fixture() {
  const t = authenticatedTest();
  const seed = await t.mutation(api.seed.ensureDemo, {});
  if (!seed.agentSpecId) throw new Error("missing spec");
  const blueprint = await t.mutation(api.blueprints.save, { agentSpecId: seed.agentSpecId, templateId: "runtime-flex", name: "Runtime Flex", mode: "guided", triggerKind: "manual", triggerLabel: "User starts", steps: [{ id: "run", label: "Run", kind: "reason", humanGate: false }], memoryPolicy: "run-only", modelPolicy: "balanced", authorityPolicy: "approval-required", evidenceLevel: "full", hardBudgetCents: 500 });
  const build = await t.mutation(api.credits.reserveBlueprint, { blueprintId: blueprint.blueprintId, idempotencyKey: "runtime-flex-build" });
  await t.mutation(api.credits.settle, { reservationId: build.reservationId, actualCredits: build.quotedCredits });
  await t.mutation(api.blueprints.activate, { blueprintId: blueprint.blueprintId, creditReservationId: build.reservationId });
  await t.mutation(api.inferenceBindings.bind, { agentSpecId: seed.agentSpecId, mode: "inherit-workspace", providerProfile: "balanced" });
  return { t, seed, blueprintId: blueprint.blueprintId };
}

describe("runtime adapters", () => {
  test("stores only opaque references and requires worker validation", async () => {
    const { t, seed } = await fixture();
    await expect(t.mutation(api.runtimeAdapters.configure, { agentSpecId: seed.agentSpecId!, engine: "mastra", label: "Unsafe", endpointRef: "https://runtime.example", secretRef: "raw-token", targetId: "agent", environment: "sandbox" })).rejects.toThrow("E_RUNTIME_ADAPTER_REFERENCE_FORBIDDEN");
    const configured = await t.mutation(api.runtimeAdapters.configure, { agentSpecId: seed.agentSpecId!, engine: "mastra", label: "Mastra production", endpointRef: "env:MASTRA_SERVER_URL", secretRef: "vault:agent-oven/mastra/token", targetId: "ops-agent", environment: "production" });
    expect(configured).toMatchObject({ marker: "RUNTIME_ADAPTER_CONFIGURED", transport: "mastra-native-v1", status: "setup-required" });
    const validated = await t.mutation(internal.runtimeAdapters.recordValidation, { runtimeAdapterId: configured.runtimeAdapterId, expectedConfigDigest: configured.configDigest, validationDigest: "reachable-proof" });
    expect(validated.marker).toBe("RUNTIME_ADAPTER_VALIDATED");
    expect(await t.query(api.runtimeAdapters.list, { agentSpecId: seed.agentSpecId! })).toEqual([expect.objectContaining({ status: "ready", endpointRef: "env:MASTRA_SERVER_URL", secretRef: "vault:agent-oven/mastra/token" })]);
  });

  test("pins a validated adapter and prepares one idempotent dispatch contract", async () => {
    const { t, seed, blueprintId } = await fixture();
    const configured = await t.mutation(api.runtimeAdapters.configure, { agentSpecId: seed.agentSpecId!, engine: "langgraph", label: "LangGraph bridge", endpointRef: "env:LANGGRAPH_BRIDGE_URL", secretRef: "env:LANGGRAPH_BRIDGE_TOKEN", targetId: "migration-graph", environment: "sandbox" });
    await t.mutation(internal.runtimeAdapters.recordValidation, { runtimeAdapterId: configured.runtimeAdapterId, expectedConfigDigest: configured.configDigest, validationDigest: "bridge-proof" });
    const queued = await t.mutation(api.execution.enqueue, { blueprintId, runtimeAdapterId: configured.runtimeAdapterId, idempotencyKey: "adapter-job", inputRef: "object://inputs/adapter.json", inputDigest: "adapter-input", maxAttempts: 2 });
    expect(queued).toMatchObject({ adapterMarker: "RUNTIME_ADAPTER_PINNED", runtimeEngine: "langgraph" });
    if (queued.quotedRuntimeCredits === undefined) throw new Error("expected runtime credit quote");
    const claimed = await t.mutation(internal.execution.claim, { jobId: queued.jobId, workerId: "worker-runtime" });
    expect(claimed).toMatchObject({ dispatchMarker: "RUNTIME_DISPATCH_PREPARED", endpointRef: "env:LANGGRAPH_BRIDGE_URL", secretRef: "env:LANGGRAPH_BRIDGE_TOKEN", dispatch: { schema: "agent-oven.dispatch.v1", engine: "langgraph", targetId: "migration-graph", inputDigest: "adapter-input", adapterConfigDigest: configured.configDigest } });
    await expect(t.mutation(internal.execution.complete, { jobId: queued.jobId, workerId: "worker-runtime", resultDigest: "result", actualPlatformCredits: queued.quotedRuntimeCredits })).rejects.toThrow("E_RUNTIME_EXTERNAL_RUN_ID_REQUIRED");
    await expect(t.mutation(internal.execution.complete, { jobId: queued.jobId, workerId: "worker-runtime", resultDigest: "result", externalRunId: "langgraph-run-1", actualPlatformCredits: queued.quotedRuntimeCredits })).resolves.toMatchObject({ marker: "HOSTED_EXECUTION_COMPLETED" });
  });

  test("rejects configuration drift before worker execution", async () => {
    const { t, seed, blueprintId } = await fixture();
    const first = await t.mutation(api.runtimeAdapters.configure, { agentSpecId: seed.agentSpecId!, engine: "mastra", label: "Mastra A", endpointRef: "env:MASTRA_URL_A", targetId: "agent-a", environment: "sandbox" });
    await t.mutation(internal.runtimeAdapters.recordValidation, { runtimeAdapterId: first.runtimeAdapterId, expectedConfigDigest: first.configDigest, validationDigest: "proof-a" });
    const queued = await t.mutation(api.execution.enqueue, { blueprintId, runtimeAdapterId: first.runtimeAdapterId, idempotencyKey: "drift-job", inputRef: "object://inputs/drift.json", inputDigest: "drift-input", maxAttempts: 1 });
    const changed = await t.mutation(api.runtimeAdapters.configure, { agentSpecId: seed.agentSpecId!, engine: "mastra", label: "Mastra B", endpointRef: "env:MASTRA_URL_B", targetId: "agent-b", environment: "sandbox" });
    await t.mutation(internal.runtimeAdapters.recordValidation, { runtimeAdapterId: changed.runtimeAdapterId, expectedConfigDigest: changed.configDigest, validationDigest: "proof-b" });
    await expect(t.mutation(internal.execution.claim, { jobId: queued.jobId, workerId: "worker-runtime" })).rejects.toThrow("E_RUNTIME_ADAPTER_DIGEST_MISMATCH");
  });
});
