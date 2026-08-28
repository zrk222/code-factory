import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";

describe("adaptable knowledge connector definitions", () => {
  test("stores only source metadata and opaque secret references", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    const configured = await t.mutation(api.knowledgeConnectors.configure, { workspaceId: seed.workspaceId, agentSpecId: seed.agentSpecId, provider: "s3", label: "Operations manuals", sourceLocator: "s3://company-knowledge/ops/", secretRef: "env:KNOWLEDGE_S3_ROLE", syncMode: "daily" });
    expect(configured).toMatchObject({ marker: "KNOWLEDGE_CONNECTOR_CONFIGURED", credentialMarker: "RAW_CREDENTIAL_ABSENT", status: "setup-required" });
    const records = await t.query(api.knowledgeConnectors.list, { workspaceId: seed.workspaceId, agentSpecId: seed.agentSpecId });
    expect(records[0]).toMatchObject({ provider: "s3", secretRef: "env:KNOWLEDGE_S3_ROLE", status: "setup-required" });
  });

  test("rejects credentials embedded in a source locator", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    await expect(t.mutation(api.knowledgeConnectors.configure, { workspaceId: seed.workspaceId, agentSpecId: seed.agentSpecId, provider: "database", label: "Unsafe", sourceLocator: "postgres://user:password@db.example/knowledge", syncMode: "manual" })).rejects.toThrow("E_CONNECTOR_CREDENTIAL_IN_LOCATOR");
  });
});
