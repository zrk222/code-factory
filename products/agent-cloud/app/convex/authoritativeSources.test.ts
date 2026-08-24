import { describe, expect, test } from "vitest";
import { api, internal } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { authenticatedTest } from "./testIdentity.testSupport";
import { enforceAuthoritativeSourceAdmission } from "./sourceAdmission";
import { assertRequiredSourcesReady } from "./authoritativeSources";

async function fixture(withRuntime = false) {
  const t = authenticatedTest();
  const seed = await t.mutation(api.seed.ensureDemo, {});
  if (!seed.agentSpecId) throw new Error("missing spec");
  if (!withRuntime) return { t, seed, blueprintId: undefined };
  const blueprint = await t.mutation(api.blueprints.save, { agentSpecId: seed.agentSpecId, templateId: "regulated-source", name: "Regulated Source", mode: "guided", triggerKind: "manual", triggerLabel: "User starts", steps: [{ id: "retrieve", label: "Retrieve law", kind: "retrieve", humanGate: false }], memoryPolicy: "run-only", modelPolicy: "balanced", authorityPolicy: "approval-required", evidenceLevel: "full", hardBudgetCents: 500 });
  const build = await t.mutation(api.credits.reserveBlueprint, { blueprintId: blueprint.blueprintId, idempotencyKey: "regulated-source-build" });
  await t.mutation(api.credits.settle, { reservationId: build.reservationId, actualCredits: build.quotedCredits });
  await t.mutation(api.blueprints.activate, { blueprintId: blueprint.blueprintId, creditReservationId: build.reservationId });
  await t.mutation(api.inferenceBindings.bind, { agentSpecId: seed.agentSpecId, mode: "inherit-workspace", providerProfile: "balanced" });
  return { t, seed, blueprintId: blueprint.blueprintId };
}

type SourceDefinition = {
  agentSpecId: Id<"agentSpecs">; sourceKey: string; label: string; jurisdiction: string; publisher: string; sourceGroup: string;
  authorityCategory: "primary-law" | "official-regulator" | "official-registry" | "licensed-system-of-record" | "secondary-corroboration";
  sourceRole: "primary" | "fallback" | "corroboration"; canonicalLocator: string; endpointRef?: string; licenseRef?: string;
  freshnessSloSeconds: number; maximumAgeSeconds: number; minimumAuthoritativeSources: number; requiredForRuns: boolean;
};

const definition = (agentSpecId: Id<"agentSpecs">, overrides: Partial<SourceDefinition> = {}): SourceDefinition => ({
  agentSpecId,
  sourceKey: "canada-gazette",
  label: "Canada Gazette",
  jurisdiction: "Canada",
  publisher: "Government of Canada",
  sourceGroup: "federal-law",
  authorityCategory: "primary-law" as const,
  sourceRole: "primary" as const,
  canonicalLocator: "https://gazette.gc.ca/",
  endpointRef: "env:SOURCE_ENDPOINT_CANADA_GAZETTE",
  freshnessSloSeconds: 86_400,
  maximumAgeSeconds: 259_200,
  minimumAuthoritativeSources: 2,
  requiredForRuns: true,
  ...overrides,
});

describe("authoritative source control plane", () => {
  test("rejects credential-bearing locators and stores only opaque references", async () => {
    const { t, seed } = await fixture();
    await expect(t.mutation(api.authoritativeSources.configure, definition(seed.agentSpecId!, { canonicalLocator: "https://user:secret@example.com/?api_key=raw" }))).rejects.toThrow("E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN");
    await expect(t.mutation(api.authoritativeSources.configure, definition(seed.agentSpecId!, { endpointRef: "https://api.example.com" }))).rejects.toThrow("E_AUTHORITATIVE_SOURCE_REFERENCE_FORBIDDEN");
    expect((await t.query(api.authoritativeSources.listReadiness, { agentSpecId: seed.agentSpecId! })).sources).toHaveLength(0);
  });

  test("admits redundant official access and keeps secondary evidence out of the count", async () => {
    const { t, seed } = await fixture();
    const primary = await t.mutation(api.authoritativeSources.configure, definition(seed.agentSpecId!));
    const licensed = await t.mutation(api.authoritativeSources.configure, definition(seed.agentSpecId!, { sourceKey: "justice-laws", label: "Justice Laws", publisher: "Department of Justice", authorityCategory: "licensed-system-of-record", sourceRole: "fallback", canonicalLocator: "https://laws-lois.justice.gc.ca/", endpointRef: "env:SOURCE_ENDPOINT_JUSTICE_LAWS" }));
    const secondary = await t.mutation(api.authoritativeSources.configure, definition(seed.agentSpecId!, { sourceKey: "commentary", label: "Legal commentary", publisher: "Reviewed publisher", authorityCategory: "secondary-corroboration", sourceRole: "corroboration", canonicalLocator: "https://example.org/commentary", endpointRef: undefined }));
    const observedAt = Date.now();
    const definitions = await t.query(api.authoritativeSources.listWorkerDefinitions, { agentSpecId: seed.agentSpecId! });
    expect(definitions).toMatchObject({ marker: "SOURCE_WORKER_DEFINITIONS", posture: "deployment required", sources: expect.arrayContaining([expect.objectContaining({ sourceId: primary.sourceId, configDigest: primary.configDigest, endpointRef: "env:SOURCE_ENDPOINT_CANADA_GAZETTE" })]) });
    await expect(t.mutation(api.authoritativeSources.recordWorkerObservation, { sourceId: primary.sourceId, expectedConfigDigest: "stale-digest", observationKey: "stale-worker", outcome: "success", observedAt, latencyMs: 1, contentDigest: "stale-content" })).rejects.toThrow("E_AUTHORITATIVE_SOURCE_DIGEST_MISMATCH");
    await t.mutation(api.authoritativeSources.recordWorkerObservation, { sourceId: primary.sourceId, expectedConfigDigest: primary.configDigest, observationKey: "primary-1", outcome: "success", observedAt, latencyMs: 80, contentDigest: "digest-primary" });
    await t.mutation(internal.authoritativeSources.recordObservation, { sourceId: licensed.sourceId, observationKey: "licensed-1", outcome: "success", observedAt, latencyMs: 90, contentDigest: "digest-licensed" });
    await t.mutation(internal.authoritativeSources.recordObservation, { sourceId: licensed.sourceId, observationKey: "licensed-failure", outcome: "failure", observedAt: observedAt + 1, latencyMs: 300_000, failureCode: "timeout" });
    await t.mutation(internal.authoritativeSources.recordObservation, { sourceId: secondary.sourceId, observationKey: "secondary-1", outcome: "success", observedAt, latencyMs: 50 });
    const unchanged = await t.mutation(api.authoritativeSources.configure, definition(seed.agentSpecId!));
    expect(unchanged.status).toBe("ready");
    const readiness = await t.query(api.authoritativeSources.listReadiness, { agentSpecId: seed.agentSpecId! });
    expect(readiness).toMatchObject({ governance: "supervised source assurance", groups: [expect.objectContaining({ state: "ready", qualifyingAuthoritativeSources: 2, healthyAuthoritativeSources: 1 })] });
    expect(readiness.sources.find((item) => item.sourceKey === "commentary")?.assurance.countsAsAuthoritative).toBe(false);
    const replay = await t.mutation(internal.authoritativeSources.recordObservation, { sourceId: licensed.sourceId, observationKey: "licensed-failure", outcome: "failure", observedAt: observedAt + 2, latencyMs: 1, failureCode: "unknown" });
    expect(replay.marker).toBe("SOURCE_OBSERVATION_REPLAY");
    expect((await t.query(api.authoritativeSources.listReadiness, { agentSpecId: seed.agentSpecId! })).sources.find((item) => item.sourceKey === "justice-laws")?.consecutiveFailures).toBe(1);
  });

  test("blocks execution before reserving credits or creating a job", async () => {
    const { t, seed, blueprintId } = await fixture(true);
    if (!blueprintId) throw new Error("missing blueprint");
    const secondary = await t.mutation(api.authoritativeSources.configure, definition(seed.agentSpecId!, { minimumAuthoritativeSources: 1, sourceKey: "secondary-only", label: "Secondary only", authorityCategory: "secondary-corroboration", sourceRole: "corroboration", canonicalLocator: "https://example.org/secondary", endpointRef: undefined }));
    await t.mutation(internal.authoritativeSources.recordObservation, { sourceId: secondary.sourceId, observationKey: "secondary-ready", outcome: "success", observedAt: Date.now(), latencyMs: 10 });
    await expect(t.run((ctx) => assertRequiredSourcesReady(ctx as never, seed.agentSpecId!, Date.now()))).rejects.toThrow("E_AUTHORITATIVE_SOURCES_NOT_READY:federal-law:AUTHORITATIVE_COUNT_BELOW_MINIMUM");
    await expect(t.run((ctx) => enforceAuthoritativeSourceAdmission(ctx as never, seed.agentSpecId!, Date.now()))).rejects.toThrow("E_AUTHORITATIVE_SOURCES_NOT_READY:federal-law:AUTHORITATIVE_COUNT_BELOW_MINIMUM");
    const before = await t.run(async (ctx) => ({ jobs: (await ctx.db.query("executionJobs").collect()).length, reservations: (await ctx.db.query("creditReservations").collect()).length }));
    await expect(t.mutation(api.execution.enqueue, { blueprintId, idempotencyKey: "blocked-by-source", inputRef: "object://inputs/regulatory.json", inputDigest: "source-input", maxAttempts: 1 })).rejects.toThrow("E_AUTHORITATIVE_SOURCES_NOT_READY:federal-law:AUTHORITATIVE_COUNT_BELOW_MINIMUM");
    const after = await t.run(async (ctx) => ({ jobs: (await ctx.db.query("executionJobs").collect()).length, reservations: (await ctx.db.query("creditReservations").collect()).length }));
    expect(after).toEqual(before);
  });
});
