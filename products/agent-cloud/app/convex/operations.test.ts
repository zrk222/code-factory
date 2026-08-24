import { describe, expect, test } from "vitest";
import { api, internal } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";

describe("production operations evidence", () => {
  test("returns only sanitized activation metadata to an owner", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    const result = await t.query(api.operations.productionReadiness, { workspaceId: seed.workspaceId });
    expect(result).toMatchObject({ marker: "PRODUCTION_READINESS_EXPLAINED", evidenceMarker: "READINESS_RESPONSE_REDACTED", enterpriseReady: false, summary: { total: 7 } });
    expect(result.controls).toHaveLength(7);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toMatch(/CLERK_|AGENT_OVEN_|vault:\/\/|aws-sm:\/\/|azure-kv:\/\/|gcp-sm:\/\//);
  });

  test("rejects a viewer before returning deployment readiness", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    const viewerIdentity = { subject: "operations-viewer", issuer: "https://test-idp.example", name: "operations-viewer" };
    const tokenIdentifier = `${viewerIdentity.issuer}|${viewerIdentity.subject}`;
    await t.mutation(api.access.addMember, { workspaceId: seed.workspaceId, tokenIdentifier, memberLabel: "Operations viewer", role: "viewer" });
    const viewer = t.withIdentity(viewerIdentity);
    await expect(viewer.query(api.operations.productionReadiness, { workspaceId: seed.workspaceId })).rejects.toThrow("E_ROLE_FORBIDDEN");
  });

  test("moves health from attention to verified backup and restore evidence", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    const initial = await t.query(api.operations.health, { workspaceId: seed.workspaceId });
    expect(initial.findings).toEqual(expect.arrayContaining(["BACKUP_NOT_VERIFIED", "RESTORE_DRILL_NOT_VERIFIED"]));
    const requested = await t.mutation(api.operations.requestBackup, { workspaceId: seed.workspaceId, objectRef: "s3://agent-oven-backups/tenant-a/snapshot.json.enc" });
    await t.mutation(internal.operations.completeBackup, { snapshotId: requested.snapshotId, recordCount: 42, manifestDigest: "manifest-abc" });
    const drill = await t.mutation(api.operations.requestRestoreDrill, { snapshotId: requested.snapshotId, targetEnvironment: "ephemeral-drill-001" });
    const completed = await t.mutation(internal.operations.completeRestoreDrill, { drillId: drill.drillId, rowCountMatched: true, receiptChainVerified: true, tenantIsolationVerified: true, rtoSeconds: 180, rpoSeconds: 30 });
    expect(completed).toMatchObject({ marker: "RESTORE_DRILL_PASSED", rtoSeconds: 180, rpoSeconds: 30 });
    const health = await t.query(api.operations.health, { workspaceId: seed.workspaceId });
    expect(health.findings).not.toContain("BACKUP_NOT_VERIFIED");
    expect(health.findings).not.toContain("RESTORE_DRILL_NOT_VERIFIED");
  });

  test("safeObjectRef rejects embedded credentials and non-isolated restore targets", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    await expect(t.mutation(api.operations.requestBackup, { workspaceId: seed.workspaceId, objectRef: "s3://user:password@bucket/snapshot" })).rejects.toThrow("E_BACKUP_CREDENTIAL_FORBIDDEN");
    const requested = await t.mutation(api.operations.requestBackup, { workspaceId: seed.workspaceId, objectRef: "azure-blob://backups/snapshot" });
    await t.mutation(internal.operations.completeBackup, { snapshotId: requested.snapshotId, recordCount: 1, manifestDigest: "manifest" });
    await expect(t.mutation(api.operations.requestRestoreDrill, { snapshotId: requested.snapshotId, targetEnvironment: "production" })).rejects.toThrow("E_RESTORE_TARGET_NOT_ISOLATED");
  });

  test("surfaces required authoritative-source outages in workspace health", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    const configured = await t.mutation(api.authoritativeSources.configure, { agentSpecId: seed.agentSpecId, sourceKey: "regulator", label: "Official regulator", jurisdiction: "Canada", publisher: "Regulator", sourceGroup: "regulated-data", authorityCategory: "official-regulator", sourceRole: "primary", canonicalLocator: "https://example.gc.ca/regulator", freshnessSloSeconds: 3600, maximumAgeSeconds: 10800, minimumAuthoritativeSources: 1, requiredForRuns: true });
    expect((await t.query(api.operations.health, { workspaceId: seed.workspaceId })).findings).toContain("AUTHORITATIVE_SOURCES_NOT_READY");
    await t.mutation(internal.authoritativeSources.recordObservation, { sourceId: configured.sourceId, observationKey: "reachable-1", outcome: "success", observedAt: Date.now(), latencyMs: 20 });
    const health = await t.query(api.operations.health, { workspaceId: seed.workspaceId });
    expect(health.findings).not.toContain("AUTHORITATIVE_SOURCES_NOT_READY");
    expect(health.sourceAssurance).toMatchObject({ configuredSources: 1, requiredGroups: 1, readyRequiredGroups: 1, blockedRequiredGroups: [] });
  });
});
