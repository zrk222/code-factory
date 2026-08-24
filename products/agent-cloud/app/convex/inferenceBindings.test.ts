import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";

describe("agent-level BYOK binding", () => {
  test("inherits workspace inference or binds one enabled dedicated reference", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    const inherited = await t.mutation(api.inferenceBindings.bind, { agentSpecId: seed.agentSpecId, mode: "inherit-workspace", providerProfile: "balanced" });
    expect(inherited).toMatchObject({ marker: "AGENT_INFERENCE_BOUND", status: "ready", credentialMarker: "RAW_CREDENTIAL_ABSENT" });
    const provider = await t.mutation(api.lifecycle.configureProvider, { workspaceId: seed.workspaceId, provider: "openai", label: "Dedicated close model", secretRef: "env:BOOKS_OPENAI_KEY", enabled: true });
    const dedicated = await t.mutation(api.inferenceBindings.bind, { agentSpecId: seed.agentSpecId, mode: "dedicated", providerConnectionId: provider.connectionId, providerProfile: "highest-quality" });
    expect(dedicated.status).toBe("ready");
    expect(await t.query(api.inferenceBindings.get, { agentSpecId: seed.agentSpecId })).toMatchObject({ mode: "dedicated", providerConnectionId: provider.connectionId });
  });
});
