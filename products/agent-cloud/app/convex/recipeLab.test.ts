import { describe, expect, test } from "vitest";
import { api, internal } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";

const studyArgs = (agentSpecId: string) => ({
  agentSpecId: agentSpecId as never,
  name: "Support agent recipe lab",
  useCase: "Answer support questions with grounded evidence",
  evaluationSetRef: "object://recipe-evals/support-v1.jsonl",
  evaluationSetDigest: "eval-digest-00000001",
  trialCount: 2,
  studyCredits: 200,
  trialCredits: 100,
  graceCheckpointCount: 1,
  pruneFloor: 30,
  minQuality: 70,
  maxLatencyMs: 30000,
  qualityWeight: 50,
  costWeight: 30,
  latencyWeight: 20,
  modelCandidates: ["openai/gpt-5", "anthropic/claude"],
  retrievalCandidates: [4],
  memoryCandidates: ["run-only" as const],
  authorityCandidates: ["approval-required" as const],
});

describe("agent recipe lab control plane", () => {
  test("runs bounded trials, proposes a Pareto champion, and requires independent approval", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    const created = await t.mutation(api.recipeLab.createStudy, studyArgs(seed.agentSpecId));
    const started = await t.mutation(api.recipeLab.startStudy, { studyId: created.studyId });
    expect(started).toMatchObject({ marker: "RECIPE_STUDY_STARTED", evidenceMarker: "RECIPE_CANDIDATES_GENERATED", candidateCount: 2, modelCalls: 0 });

    const first = await t.mutation(internal.recipeLab.claimTrial, { studyId: created.studyId, workerId: "hosted-worker-a" });
    await t.mutation(internal.recipeLab.recordCheckpoint, { trialId: first.trialId, checkpointNumber: 1, qualityScore: 90, cumulativeCredits: 80, cumulativeLatencyMs: 12000, policyViolations: 0 });
    expect((await t.mutation(internal.recipeLab.completeTrial, { trialId: first.trialId, qualityScore: 95, costCredits: 80, latencyMs: 12000, policyViolations: 0, evidenceDigest: "evidence-digest-first" })).eligible).toBe(true);

    const second = await t.mutation(internal.recipeLab.claimTrial, { studyId: created.studyId, workerId: "hosted-worker-b" });
    await t.mutation(internal.recipeLab.recordCheckpoint, { trialId: second.trialId, checkpointNumber: 1, qualityScore: 88, cumulativeCredits: 30, cumulativeLatencyMs: 6000, policyViolations: 0 });
    await t.mutation(internal.recipeLab.completeTrial, { trialId: second.trialId, qualityScore: 90, costCredits: 30, latencyMs: 6000, policyViolations: 0, evidenceDigest: "evidence-digest-second" });

    const finalized = await t.mutation(api.recipeLab.finalizeStudy, { studyId: created.studyId });
    expect(finalized.marker).toBe("RECIPE_CHAMPION_PROPOSED");
    if (finalized.marker !== "RECIPE_CHAMPION_PROPOSED") throw new Error("missing champion");
    await expect(t.mutation(api.recipeLab.approveChampion, { studyId: created.studyId, expectedRecipeDigest: finalized.recipeDigest })).rejects.toThrow("E_RECIPE_SELF_APPROVAL_FORBIDDEN");
    await t.mutation(api.access.addMember, { workspaceId: seed.workspaceId, tokenIdentifier: "https://test-idp.example|reviewer", memberLabel: "Independent reviewer", role: "reviewer" });
    const reviewer = t.withIdentity({ subject: "reviewer", issuer: "https://test-idp.example", name: "reviewer" });
    expect((await reviewer.mutation(api.recipeLab.approveChampion, { studyId: created.studyId, expectedRecipeDigest: finalized.recipeDigest })).marker).toBe("RECIPE_CHAMPION_APPROVED");
    const visible = await t.query(api.recipeLab.getStudy, { agentSpecId: seed.agentSpecId });
    expect(visible?.marker).toBe("RECIPE_STUDY_REDACTED");
    expect(JSON.stringify(visible)).not.toContain("object://recipe-evals");
    expect(JSON.stringify(visible)).not.toContain("hosted-worker");
  });

  test("prunes policy violations and produces no champion", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    const created = await t.mutation(api.recipeLab.createStudy, studyArgs(seed.agentSpecId));
    await t.mutation(api.recipeLab.startStudy, { studyId: created.studyId });
    for (let index = 0; index < 2; index += 1) {
      const trial = await t.mutation(internal.recipeLab.claimTrial, { studyId: created.studyId, workerId: `worker-${index}` });
      const pruned = await t.mutation(internal.recipeLab.recordCheckpoint, { trialId: trial.trialId, checkpointNumber: 1, qualityScore: 99, cumulativeCredits: 1, cumulativeLatencyMs: 1, policyViolations: 1 });
      expect(pruned).toMatchObject({ marker: "RECIPE_TRIAL_PRUNED", reasonCode: "TRIAL_POLICY_VIOLATION_PRUNED" });
    }
    expect(await t.mutation(api.recipeLab.finalizeStudy, { studyId: created.studyId })).toMatchObject({ marker: "RECIPE_STUDY_NO_CHAMPION", reasonCode: "E_RECIPE_NO_ELIGIBLE_CHAMPION" });
  });
});
