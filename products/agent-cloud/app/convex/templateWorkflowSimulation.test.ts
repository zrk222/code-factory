import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";
import { quoteBlueprintCredits } from "./pricing";
import { businessTemplates } from "../src/templates";
import { templateAutomationPacks } from "../src/templateAutomationPacks";
import { stepsForAutomation, stepsForTemplate } from "../src/templateWorkflow";

describe.each(businessTemplates)("published template simulation: $id", (template) => {
  test("saves and simulates the complete bounded workflow", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    const steps = stepsForTemplate(template);
    const saved = await t.mutation(api.blueprints.save, {
      agentSpecId: seed.agentSpecId,
      templateId: template.id,
      name: template.title,
      mode: "guided",
      triggerKind: "manual",
      triggerLabel: "User starts a run",
      steps,
      memoryPolicy: template.memory === "architecture-history" ? "governed" : "run-only",
      modelPolicy: template.tier === "Premium trust" ? "highest-quality" : "balanced",
      authorityPolicy: template.authority,
      evidenceLevel: template.tier === "Premium trust" ? "full" : "essential",
      hardBudgetCents: Math.round(template.hardBudgetDollars * 100),
    });
    const simulation = await t.query(api.blueprints.simulate, { agentSpecId: seed.agentSpecId });
    expect(saved.estimatedPlatformCredits, template.id).toBeGreaterThan(0);
    expect(simulation, template.id).toMatchObject({ marker: "AGENT_BLUEPRINT_SIMULATED", ready: true, maxInferenceCostCents: Math.round(template.hardBudgetDollars * 100) });
    expect(simulation?.stages.map((stage) => stage.label), template.id).toEqual(template.loop);
    expect(simulation?.stages.at(-1)?.humanGate, template.id).toBe(template.authority === "approval-required");
    expect(quoteBlueprintCredits({ templateId: template.id, steps, triggerKind: "manual", memoryPolicy: template.memory, evidenceLevel: template.tier === "Premium trust" ? "full" : "essential" }).pricingMode, template.id).toBe("fixed-template");
  });
});
const automationCases = templateAutomationPacks.flatMap((pack) => pack.automations.map((automation, automationIndex) => ({ pack, automation, automationIndex })));

describe.each(automationCases)("preset automation simulation: $pack.templateId / $automation.name", ({ pack, automation, automationIndex }) => {
  test("saves and simulates every human-owned automation stage", async () => {
    const template = businessTemplates.find((candidate) => candidate.id === pack.templateId);
    expect(template, pack.templateId).toBeDefined();
    if (!template) return;
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    const steps = stepsForAutomation(pack.templateId, automationIndex, automation.steps);
    await t.mutation(api.blueprints.save, {
      agentSpecId: seed.agentSpecId,
      templateId: template.id,
      name: automation.name,
      mode: "guided",
      triggerKind: "event",
      triggerLabel: automation.when,
      steps,
      memoryPolicy: "governed",
      modelPolicy: "highest-quality",
      authorityPolicy: "approval-required",
      evidenceLevel: "full",
      hardBudgetCents: Math.round(template.hardBudgetDollars * 100),
    });
    const simulation = await t.query(api.blueprints.simulate, { agentSpecId: seed.agentSpecId });
    expect(simulation, `${pack.templateId}/${automation.name}`).toMatchObject({ marker: "AGENT_BLUEPRINT_SIMULATED", ready: true, approvalRequired: true });
    expect(simulation?.stages.map((stage) => stage.label), automation.name).toEqual(automation.steps);
    expect(simulation?.stages.at(-1)?.humanGate, automation.name).toBe(true);
    expect(automation.stopIf.length, automation.name).toBeGreaterThanOrEqual(3);
  });
});
