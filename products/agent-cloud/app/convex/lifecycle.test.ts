import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import { canonicalAgentSpec, parseAgentSpecImport, receiptFingerprint } from "./domain";
import schema from "./schema";
import { authenticatedTest } from "./testIdentity.testSupport";

const modules = import.meta.glob("./**/*.ts");

async function seeded() {
  const t = authenticatedTest();
  const result = await t.mutation(api.seed.ensureDemo, {});
  if (!result.agentSpecId) throw new Error("seed did not create an AgentSpec");
  return { t, ...result };
}

describe("AgentSpec operator lifecycle", () => {
  test("exports, imports, and rolls back through append-only versions", async () => {
    const { t, agentSpecId } = await seeded();
    const exported = await t.query(api.lifecycle.exportAgentSpec, { agentSpecId });
    expect(exported.marker).toBe("AGENT_SPEC_EXPORTED");
    expect(exported.digest).toMatch(/^[0-9a-f]{16}$/);
    expect(Object.keys(JSON.parse(exported.canonical))).toHaveLength(7);

    const importedPayload = JSON.stringify({
      ...JSON.parse(exported.canonical),
      repository: "acme/versioned-ledger",
      hardBudgetCents: 620,
    });
    const importedDigest = receiptFingerprint([canonicalAgentSpec(parseAgentSpecImport(importedPayload))]);
    const imported = await t.mutation(api.lifecycle.importAgentSpec, {
      agentSpecId,
      canonical: importedPayload,
      digest: importedDigest,
    });
    expect(imported).toMatchObject({ marker: "AGENT_SPEC_IMPORTED", version: 2 });

    const rolledBack = await t.mutation(api.lifecycle.rollbackAgentSpec, { agentSpecId, targetVersion: 1 });
    expect(rolledBack).toMatchObject({ marker: "AGENT_SPEC_ROLLED_BACK", restoredFromVersion: 1, version: 3 });
    const state = await t.run(async (ctx) => ({
      spec: await ctx.db.get(agentSpecId),
      versions: await ctx.db.query("agentSpecVersions").collect(),
    }));
    expect(state.spec?.repository).toBe("zrk222/code-factory");
    expect(state.versions.map((item) => item.version)).toEqual([1, 2, 3]);
    expect(state.versions.map((item) => item.source)).toEqual(["seed", "import", "rollback"]);
  });

  test("rejects forged and malformed imports before writes", async () => {
    const { t, agentSpecId } = await seeded();
    const exported = await t.query(api.lifecycle.exportAgentSpec, { agentSpecId });
    await expect(t.mutation(api.lifecycle.importAgentSpec, {
      agentSpecId,
      canonical: exported.canonical,
      digest: "0000000000000000",
    })).rejects.toThrow("E_IMPORT_DIGEST_MISMATCH");
    await expect(t.mutation(api.lifecycle.importAgentSpec, {
      agentSpecId,
      canonical: "{not-json",
      digest: exported.digest,
    })).rejects.toThrow("E_INVALID_IMPORT");
    const count = await t.run(async (ctx) => (await ctx.db.query("agentSpecVersions").collect()).length);
    expect(count).toBe(1);
  });

  test("pauses pending authority, resumes, and makes revoke permanent", async () => {
    const { t, agentSpecId } = await seeded();
    const launched = await t.mutation(api.control.launchRun, {
      agentSpecId,
      branch: "feature/lifecycle",
      commitSha: "c".repeat(40),
      estimatedCostCents: 90,
    });
    const paused = await t.mutation(api.lifecycle.setLifecycle, {
      agentSpecId,
      action: "pause",
      reason: "Operator emergency stop exercise.",
    });
    expect(paused).toMatchObject({ marker: "AGENT_EMERGENCY_STOPPED", closedRuns: 1, closedApprovals: 1 });
    const detail = await t.query(api.control.runDetail, { runId: launched.runId });
    expect(detail?.run.status).toBe("blocked");
    expect(detail?.approval?.status).toBe("rejected");
    await expect(t.mutation(api.control.launchRun, {
      agentSpecId,
      branch: "feature/blocked",
      commitSha: "d".repeat(40),
      estimatedCostCents: 50,
    })).rejects.toThrow("E_AGENT_NOT_ACTIVE");

    const resumed = await t.mutation(api.lifecycle.setLifecycle, {
      agentSpecId,
      action: "resume",
      reason: "Incident cleared after review.",
    });
    expect(resumed).toMatchObject({ marker: "AGENT_RESUMED", status: "active" });
    const revoked = await t.mutation(api.lifecycle.setLifecycle, {
      agentSpecId,
      action: "revoke",
      reason: "Agent retired permanently.",
    });
    expect(revoked).toMatchObject({ marker: "AGENT_PERMANENTLY_REVOKED", status: "revoked" });
    await expect(t.mutation(api.lifecycle.setLifecycle, {
      agentSpecId,
      action: "resume",
      reason: "Attempted unauthorized restart.",
    })).rejects.toThrow("E_AGENT_REVOKED");
  });

  test("stores two provider references and rejects raw credential material", async () => {
    const { t, workspaceId } = await seeded();
    await expect(t.mutation(api.lifecycle.configureProvider, {
      workspaceId,
      provider: "openai",
      label: "Unsafe raw value",
      secretRef: "sk-not-a-real-key",
      enabled: true,
    })).rejects.toThrow("E_RAW_SECRET_FORBIDDEN");
    await expect(t.mutation(api.lifecycle.configureProvider, {
      workspaceId,
      provider: "openai",
      label: "Wrong scheme",
      secretRef: "https://secrets.example/key",
      enabled: true,
    })).rejects.toThrow("E_INVALID_SECRET_REF");
    await t.mutation(api.lifecycle.configureProvider, {
      workspaceId,
      provider: "openai",
      label: "OpenAI production",
      secretRef: "env:OPENAI_API_KEY",
      enabled: true,
    });
    await t.mutation(api.lifecycle.configureProvider, {
      workspaceId,
      provider: "anthropic",
      label: "Anthropic team vault",
      secretRef: "vault:anthropic/team-alpha",
      enabled: true,
    });
    const connections = await t.run(async (ctx) => ctx.db.query("providerConnections").collect());
    expect(connections).toHaveLength(2);
    expect(connections.every((item) => item.status === "enabled")).toBe(true);
    expect(JSON.stringify(connections)).not.toContain("not-a-real-key");
  });
});
