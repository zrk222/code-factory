import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import schema from "./schema";
import { authenticatedTest } from "./testIdentity.testSupport";

const modules = import.meta.glob("./**/*.ts");
const checks = ["containment-verified", "evidence-preserved", "root-cause-recorded", "rollback-verified", "owner-approved"] as const;
async function seeded() { const t = authenticatedTest(); const seed = await t.mutation(api.seed.ensureDemo, {}); if (!seed.agentSpecId) throw new Error("missing spec"); return { t, ...seed }; }

describe("incident readiness", () => {
  test("contains agent authority, pending work, and active canary atomically", async () => {
    const { t, agentSpecId } = await seeded();
    await t.mutation(api.control.launchRun, { agentSpecId, branch: "incident/drill", commitSha: "a".repeat(40), estimatedCostCents: 40 });
    await t.mutation(api.releases.startCanary, { agentSpecId, targetVersion: 1, deterministicGatesPassed: 6, modelScore: 88, trafficPercent: 10, reason: "incident drill" });
    const incident = await t.mutation(api.incidents.openIncident, { agentSpecId, severity: "sev1", summary: "Provider responses violated the release invariant." });
    expect(incident).toMatchObject({ marker: "INCIDENT_CONTAINED", authorityMarker: "INCIDENT_AUTHORITY_CLOSED", canaryMarker: "INCIDENT_CANARY_ROLLED_BACK", closedRuns: 1, closedApprovals: 1, rolledBackCanaries: 1 });
    const state = await t.run(async (ctx) => ({ spec: await ctx.db.get(agentSpecId), runs: await ctx.db.query("runs").collect(), approvals: await ctx.db.query("approvals").collect(), canaries: await ctx.db.query("releaseCandidates").collect() }));
    expect(state.spec?.status).toBe("suspended"); expect(state.runs[0].status).toBe("blocked"); expect(state.approvals[0].status).toBe("rejected"); expect(state.canaries[0].status).toBe("rolled-back");
    await expect(t.mutation(api.incidents.openIncident, { agentSpecId, severity: "sev2", summary: "duplicate" })).rejects.toThrow("E_INCIDENT_ACTIVE");
  });

  test("rejects duplicate checks and incomplete recovery without writes", async () => {
    const { t, agentSpecId } = await seeded();
    const incident = await t.mutation(api.incidents.openIncident, { agentSpecId, severity: "sev2", summary: "Recovery contract exercise." });
    await t.mutation(api.incidents.recordRecoveryCheck, { incidentId: incident.incidentId, check: checks[0] });
    await expect(t.mutation(api.incidents.recordRecoveryCheck, { incidentId: incident.incidentId, check: checks[0] })).rejects.toThrow("E_RECOVERY_CHECK_DUPLICATE");
    await expect(t.mutation(api.incidents.resolveIncident, { incidentId: incident.incidentId, resolutionNote: "too early" })).rejects.toThrow("E_RECOVERY_INCOMPLETE");
    const spec = await t.run(async (ctx) => ctx.db.get(agentSpecId)); expect(spec?.status).toBe("suspended");
  });

  test("resolves only after five distinct recovery checks", async () => {
    const { t, agentSpecId } = await seeded();
    const incident = await t.mutation(api.incidents.openIncident, { agentSpecId, severity: "sev2", summary: "Exercise the complete runbook." });
    for (const check of checks) expect((await t.mutation(api.incidents.recordRecoveryCheck, { incidentId: incident.incidentId, check })).marker).toBe("RECOVERY_CHECK_RECORDED");
    const resolved = await t.mutation(api.incidents.resolveIncident, { incidentId: incident.incidentId, resolutionNote: "Recovery owner approved return to service." });
    expect(resolved).toMatchObject({ marker: "INCIDENT_RESOLVED", checks: 5, agentStatus: "active" });
    const receipts = await t.run(async (ctx) => (await ctx.db.query("receipts").collect()).filter((item) => item.type === "incident-response")); expect(receipts).toHaveLength(2);
  });
});
