import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";

const description = "Monitor GitHub pull requests and verify requirements and tests within 10 minutes. Read the repository only, never merge code, stop on missing evidence, retry one transient API timeout, and escalate every failed or unknown check to a human reviewer using checkpoints.";

describe("portable agent composer API", () => {
  test("stores a digest-bound draft without the raw brief", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    const result = await t.mutation(api.agentComposer.compile, { agentSpecId: seed.agentSpecId, description, runtimePreference: "auto", inferenceAccess: "agent-oven-api" });
    expect(result).toMatchObject({ marker: "AGENT_INTENT_COMPILED", selectedRuntime: "langgraph", rawDescriptionStored: false });
    const stored = await t.run(async (ctx) => ctx.db.get(result.draftId));
    expect(stored).not.toHaveProperty("description");
    expect(stored).toMatchObject({ intentDigest: result.intentDigest, compilerDigest: result.compilerDigest, status: "ready" });
    const latest = await t.query(api.agentComposer.latest, { agentSpecId: seed.agentSpecId });
    expect(latest.compatibility).toHaveLength(3);
    expect(latest.drafts).toHaveLength(1);
  });
});
