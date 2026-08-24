import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import schema from "./schema";
import { authenticatedTest } from "./testIdentity.testSupport";

const modules = import.meta.glob("./**/*.ts");
async function seeded() { const t = authenticatedTest(); const seed = await t.mutation(api.seed.ensureDemo, {}); if (!seed.agentSpecId) throw new Error("missing spec"); return { t, ...seed }; }

describe("release safety", () => {
  test("requires re-evaluation and one bounded active canary", async () => {
    const { t, agentSpecId } = await seeded();
    await expect(t.mutation(api.releases.startCanary, { agentSpecId, targetVersion: 1, deterministicGatesPassed: 5, modelScore: 88, trafficPercent: 10, reason: "test" })).rejects.toThrow("E_REEVALUATION_REQUIRED");
    const started = await t.mutation(api.releases.startCanary, { agentSpecId, targetVersion: 1, deterministicGatesPassed: 6, modelScore: 88, trafficPercent: 10, reason: "evaluated model change" });
    expect(started.marker).toBe("CANARY_STARTED");
    await expect(t.mutation(api.releases.startCanary, { agentSpecId, targetVersion: 1, deterministicGatesPassed: 6, modelScore: 90, trafficPercent: 10, reason: "duplicate" })).rejects.toThrow("E_CANARY_ACTIVE");
  });

  test("promotes only after twenty healthy observations", async () => {
    const { t, agentSpecId } = await seeded();
    const failing = await t.mutation(api.releases.startCanary, { agentSpecId, targetVersion: 1, deterministicGatesPassed: 6, modelScore: 91, trafficPercent: 10, reason: "failure control" });
    for (let index = 0; index < 19; index += 1) await t.mutation(api.releases.recordObservation, { candidateId: failing.candidateId, failed: false });
    await t.mutation(api.releases.recordObservation, { candidateId: failing.candidateId, failed: true });
    await expect(t.mutation(api.releases.promoteCanary, { candidateId: failing.candidateId })).rejects.toThrow("E_CANARY_NOT_READY");
    await t.mutation(api.releases.rollbackCanary, { candidateId: failing.candidateId, reason: "failed canary" });
    const started = await t.mutation(api.releases.startCanary, { agentSpecId, targetVersion: 1, deterministicGatesPassed: 6, modelScore: 91, trafficPercent: 10, reason: "healthy" });
    await expect(t.mutation(api.releases.promoteCanary, { candidateId: started.candidateId })).rejects.toThrow("E_CANARY_NOT_READY");
    for (let index = 0; index < 20; index += 1) await t.mutation(api.releases.recordObservation, { candidateId: started.candidateId, failed: false });
    const promoted = await t.mutation(api.releases.promoteCanary, { candidateId: started.candidateId });
    expect(promoted.marker).toBe("CANARY_PROMOTED");
  });

  test("rolls back with append-only evidence", async () => {
    const { t, agentSpecId } = await seeded();
    const started = await t.mutation(api.releases.startCanary, { agentSpecId, targetVersion: 1, deterministicGatesPassed: 6, modelScore: 84, trafficPercent: 5, reason: "bounded" });
    const rolled = await t.mutation(api.releases.rollbackCanary, { candidateId: started.candidateId, reason: "operator recovery drill" });
    expect(rolled.marker).toBe("CANARY_ROLLED_BACK");
    const receipts = await t.run(async (ctx) => (await ctx.db.query("receipts").collect()).filter((item) => item.type === "release-safety"));
    expect(receipts).toHaveLength(2);
  });
});
