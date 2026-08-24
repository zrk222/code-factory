import { describe, expect, test } from "vitest";
import { api, internal } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";

const base = { templateId: "community-memory-guide", name: "Community Memory Guide", mode: "guided" as const, triggerKind: "manual" as const, triggerLabel: "User starts a run", steps: [{ id: "retrieve", label: "Retrieve permitted threads", kind: "retrieve" as const, humanGate: false }, { id: "answer", label: "Answer with attribution", kind: "validate" as const, humanGate: true }], memoryPolicy: "governed" as const, modelPolicy: "balanced" as const, authorityPolicy: "approval-required" as const, evidenceLevel: "full" as const, hardBudgetCents: 2000 };

describe("versioned Agent Blueprint", () => {
  test("saves immutable versions, simulates, and activates a ready manual workflow", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    const first = await t.mutation(api.blueprints.save, { agentSpecId: seed.agentSpecId, ...base });
    expect(first).toMatchObject({ marker: "AGENT_BLUEPRINT_SAVED", version: 1, estimatedPlatformCredits: 85, status: "draft" });
    const second = await t.mutation(api.blueprints.save, { agentSpecId: seed.agentSpecId, ...base, mode: "architect" });
    expect(second.version).toBe(2);
    const simulation = await t.query(api.blueprints.simulate, { agentSpecId: seed.agentSpecId });
    expect(simulation).toMatchObject({ marker: "AGENT_BLUEPRINT_SIMULATED", ready: true, approvalRequired: true, estimatedPlatformCredits: 85 });
    const reserved = await t.mutation(api.credits.reserveBlueprint, { blueprintId: second.blueprintId, idempotencyKey: "activate-community-v2" });
    await t.mutation(api.credits.settle, { reservationId: reserved.reservationId, actualCredits: reserved.quotedCredits });
    const activated = await t.mutation(api.blueprints.activate, { blueprintId: second.blueprintId, creditReservationId: reserved.reservationId });
    expect(activated.marker).toBe("AGENT_BLUEPRINT_ACTIVATED");
    const state = await t.query(api.blueprints.get, { agentSpecId: seed.agentSpecId });
    expect(state?.blueprint.status).toBe("active");
    expect(state?.versions).toHaveLength(2);
  });

  test("blocks activation when a workflow connector lacks tenant authorization", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    const saved = await t.mutation(api.blueprints.save, { agentSpecId: seed.agentSpecId, ...base, steps: [{ id: "drive", label: "Read operations folder", kind: "retrieve", connectorProvider: "google-drive", humanGate: false }] });
    const simulation = await t.query(api.blueprints.simulate, { agentSpecId: seed.agentSpecId });
    expect(simulation).toMatchObject({ ready: false, blockers: ["Connector google-drive is not authorized."] });
    const reserved = await t.mutation(api.credits.reserveBlueprint, { blueprintId: saved.blueprintId, idempotencyKey: "blocked-drive" });
    await t.mutation(api.credits.settle, { reservationId: reserved.reservationId, actualCredits: reserved.quotedCredits });
    await expect(t.mutation(api.blueprints.activate, { blueprintId: saved.blueprintId, creditReservationId: reserved.reservationId })).rejects.toThrow("E_BLUEPRINT_CONNECTOR_NOT_READY");
  });

  test("blocks an external runtime until its exact adapter is validated", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    const saved = await t.mutation(api.blueprints.save, { agentSpecId: seed.agentSpecId, ...base, runtimeEngine: "langgraph", inferenceAccess: "agent-oven-api" });
    await expect(t.query(api.blueprints.simulate, { agentSpecId: seed.agentSpecId })).resolves.toMatchObject({ ready: false, runtimeEngine: "langgraph", inferenceAccess: "agent-oven-api", blockers: ["langgraph runtime adapter is not validated."] });
    const reserved = await t.mutation(api.credits.reserveBlueprint, { blueprintId: saved.blueprintId, idempotencyKey: "blocked-langgraph" });
    await t.mutation(api.credits.settle, { reservationId: reserved.reservationId, actualCredits: reserved.quotedCredits });
    await expect(t.mutation(api.blueprints.activate, { blueprintId: saved.blueprintId, creditReservationId: reserved.reservationId })).rejects.toThrow("E_BLUEPRINT_RUNTIME_ADAPTER_NOT_READY");
    const configured = await t.mutation(api.runtimeAdapters.configure, { agentSpecId: seed.agentSpecId, engine: "langgraph", label: "Portable graph", endpointRef: "env:LANGGRAPH_BRIDGE_URL", targetId: "portable-agent", environment: "sandbox" });
    await t.mutation(internal.runtimeAdapters.recordValidation, { runtimeAdapterId: configured.runtimeAdapterId, expectedConfigDigest: configured.configDigest, validationDigest: "reachable-proof" });
    await expect(t.query(api.blueprints.simulate, { agentSpecId: seed.agentSpecId })).resolves.toMatchObject({ ready: true, blockers: [] });
    await expect(t.mutation(api.blueprints.activate, { blueprintId: saved.blueprintId, creditReservationId: reserved.reservationId })).resolves.toMatchObject({ marker: "AGENT_BLUEPRINT_ACTIVATED" });
  });
});
