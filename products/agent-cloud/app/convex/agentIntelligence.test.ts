import { describe, expect, test } from "vitest";
import { api, internal } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";
import { evaluateCompliancePath, redactOperationalText } from "./agentIntelligenceDomain";

async function activeJob() {
  const t = authenticatedTest();
  const seed = await t.mutation(api.seed.ensureDemo, {});
  if (!seed.agentSpecId) throw new Error("missing spec");
  const blueprint = await t.mutation(api.blueprints.save, { agentSpecId: seed.agentSpecId, templateId: "governed", name: "Governed", mode: "guided", triggerKind: "manual", triggerLabel: "User starts", steps: [{ id: "plan", label: "Plan", kind: "reason", humanGate: false }, { id: "act", label: "Act", kind: "act", humanGate: true }], memoryPolicy: "governed", modelPolicy: "auto", authorityPolicy: "approval-required", evidenceLevel: "full", hardBudgetCents: 500 });
  const build = await t.mutation(api.credits.reserveBlueprint, { blueprintId: blueprint.blueprintId, idempotencyKey: "activate-governed" });
  await t.mutation(api.credits.settle, { reservationId: build.reservationId, actualCredits: build.quotedCredits });
  await t.mutation(api.blueprints.activate, { blueprintId: blueprint.blueprintId, creditReservationId: build.reservationId });
  await t.mutation(api.inferenceBindings.bind, { agentSpecId: seed.agentSpecId, mode: "inherit-workspace", providerProfile: "balanced" });
  return { t, ...seed, blueprintId: blueprint.blueprintId };
}

describe("governed runtime intelligence", () => {
  test("publishes a frozen preset, pins it, clarifies, records transparent evidence, and resumes by digest", async () => {
    const { t, agentSpecId, blueprintId } = await activeJob();
    if (!agentSpecId) throw new Error("missing spec");
    const preset = await t.mutation(api.agentIntelligence.savePreset, { agentSpecId, name: "Safe operations", updateChannel: "frozen", maxSteps: 24, maxInputTokens: 120000, maxOutputTokens: 12000, maxReasoningTokens: 24000, allowedModels: ["openai/gpt-5"], allowedTools: ["knowledge.search", "human.approval"], allowedWorkflows: ["plan-gather-check-act"], sourceAllowDomains: ["docs.example.com"], sourceDenyDomains: ["spam.example"], recencyDays: 30, country: "CA", region: "Ontario", city: "Toronto", requireClarification: true, rubricVersion: "runtime.v1" });
    expect(await t.mutation(api.agentIntelligence.publishPreset, { presetId: preset.presetId, expectedDigest: preset.digest })).toMatchObject({ marker: "GOVERNED_PRESET_PUBLISHED", updateChannel: "frozen" });
    const queued = await t.mutation(api.execution.enqueue, { blueprintId, idempotencyKey: "governed-job", inputRef: "object://inputs/governed.json", inputDigest: "input-digest", maxAttempts: 2 });
    const job = await t.run((ctx) => ctx.db.get(queued.jobId));
    expect(job?.runtimePresetVersion).toBe(preset.version);
    const clarification = await t.mutation(api.agentIntelligence.addClarification, { jobId: queued.jobId, questionId: "desired-outcome", question: "Which result should be approved?", required: true });
    await expect(t.mutation(internal.execution.claim, { jobId: queued.jobId, workerId: "worker-a" })).rejects.toThrow("E_CLARIFICATION_REQUIRED");
    const initial = await t.query(api.agentIntelligence.runIntelligence, { jobId: queued.jobId });
    const automatic = initial.clarifications.find((item) => item.questionId === "confirm-outcome");
    if (!automatic) throw new Error("missing automatic clarification");
    await t.mutation(api.agentIntelligence.answerClarification, { clarificationId: automatic._id, answer: "Deliver the approved report." });
    await t.mutation(api.agentIntelligence.answerClarification, { clarificationId: clarification.clarificationId, answer: "Create an editable report." });
    await t.mutation(internal.execution.claim, { jobId: queued.jobId, workerId: "worker-a" });
    await t.mutation(internal.agentIntelligence.recordProgress, { jobId: queued.jobId, sequence: 1, phase: "plan", summary: "Plan for jane@example.com with api_key=super-secret", evidenceClass: "observed" });
    await t.mutation(internal.agentIntelligence.recordFinding, { jobId: queued.jobId, title: "Source finding", summary: "Call +1 (416) 555-0111 after review", sourceRef: "https://docs.example.com/policy", sourceDigest: "source-digest", contradiction: true });
    await t.mutation(internal.agentIntelligence.recordUsage, { jobId: queued.jobId, provider: "openai", model: "gpt-5", cachedInputTokens: 2000, inputTokens: 3000, outputTokens: 400, reasoningTokens: 600, providerCostMicros: 125000, latencyMs: 900, toolSteps: 3 });
    await t.mutation(internal.agentIntelligence.recordArtifact, { jobId: queued.jobId, label: "Editable report", objectRef: "object://artifacts/report.md", digest: "artifact-digest", mediaType: "text/markdown", editable: true });
    await t.mutation(internal.agentIntelligence.recordScore, { jobId: queued.jobId, component: "accuracy", method: "deterministic", score: 94, rubricVersion: "runtime.v1", evidenceDigest: "score-digest" });
    await expect(t.mutation(internal.agentIntelligence.recordUsage, { jobId: queued.jobId, provider: "unknown", model: "unapproved", cachedInputTokens: 0, inputTokens: 1, outputTokens: 1, reasoningTokens: 0, providerCostMicros: 1, latencyMs: 1, toolSteps: 1 })).rejects.toThrow("E_RUNTIME_MODEL_NOT_ALLOWED");
    await t.mutation(internal.agentIntelligence.suspendJob, { jobId: queued.jobId, sequence: 1, currentStepId: "act", executedPath: ["plan"], outputRefs: ["object://artifacts/report.md"], reason: "Waiting for exact approval", resumeDigest: "resume-abc" });
    await expect(t.mutation(api.agentIntelligence.resumeJob, { jobId: queued.jobId, resumeDigest: "wrong" })).rejects.toThrow("E_RESUME_DIGEST_MISMATCH");
    expect((await t.mutation(api.agentIntelligence.resumeJob, { jobId: queued.jobId, resumeDigest: "resume-abc" })).marker).toBe("RUN_SNAPSHOT_RESUMED");
    const intelligence = await t.query(api.agentIntelligence.runIntelligence, { jobId: queued.jobId });
    expect(intelligence).toMatchObject({ marker: "GOVERNED_RUN_EXPLAINED", usage: [{ cachedInputTokens: 2000, providerCostMicros: 125000 }], artifacts: [{ editable: true }], scores: [{ component: "accuracy", score: 94 }] });
    expect(JSON.stringify(intelligence)).not.toContain("super-secret");
    expect(JSON.stringify(intelligence)).not.toContain("jane@example.com");
    expect(JSON.stringify(intelligence)).not.toContain("416) 555");
  });

  test("validates operations-manual trace rules deterministically", () => {
    expect(evaluateCompliancePath(["plan", "approve", "act"], ["act"], [{ ruleId: "approval-first", predicate: "required-before", subjectStep: "act", relatedStep: "approve" }, { ruleId: "human-act", predicate: "requires-human-gate", subjectStep: "act" }])).toEqual({ passed: true, violations: [] });
    expect(evaluateCompliancePath(["plan", "act"], [], [{ ruleId: "approval-first", predicate: "required-before", subjectStep: "act", relatedStep: "approve" }])).toEqual({ passed: false, violations: ["approval-first"] });
    expect(redactOperationalText("password=hunter2 and a@b.com")).toBe("[REDACTED_SECRET] and [REDACTED_EMAIL]");
  });
});
