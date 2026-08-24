import { describe, expect, test } from "vitest";
import { api, internal } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";

describe("remote database tools", () => {
  test("allows named reads and requires a distinct exact approval for writes", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    const connection = await t.mutation(api.databaseTools.configureConnection, { agentSpecId: seed.agentSpecId, engine: "postgresql", label: "Operations", endpointRef: "env:DATABASE_ENDPOINT", secretRef: "vault:agent-oven/database/operations", allowedNamespaces: ["operations"] });
    await t.mutation(internal.databaseTools.activateConnection, { connectionId: connection.connectionId, validationDigest: "validated-adapter" });
    const read = await t.mutation(api.databaseTools.registerOperation, { connectionId: connection.connectionId, operationKey: "open_orders", label: "Open orders", mode: "read", executionKind: "view", target: "operations.open_orders", parameterNames: ["workspace_id"] });
    await t.mutation(api.databaseTools.publishOperation, { operationId: read.operationId });
    const readRequest = await t.mutation(api.databaseTools.requestOperation, { operationId: read.operationId, parametersRef: "object://database-params/read.json", parametersDigest: "read-digest" });
    expect(readRequest.marker).toBe("DATABASE_READ_QUEUED");
    expect((await t.mutation(internal.databaseTools.completeOperation, { requestId: readRequest.requestId, succeeded: true, resultDigest: "rows-digest" })).marker).toBe("REMOTE_DATABASE_OPERATION_COMPLETED");

    const write = await t.mutation(api.databaseTools.registerOperation, { connectionId: connection.connectionId, operationKey: "close_order", label: "Close order", mode: "write", executionKind: "stored-procedure", target: "operations.close_order", parameterNames: ["workspace_id", "order_id"] });
    await t.mutation(api.databaseTools.publishOperation, { operationId: write.operationId });
    const writeRequest = await t.mutation(api.databaseTools.requestOperation, { operationId: write.operationId, parametersRef: "object://database-params/write.json", parametersDigest: "write-digest" });
    expect(writeRequest.marker).toBe("DATABASE_WRITE_AWAITING_APPROVAL");
    await expect(t.mutation(api.databaseTools.approveWrite, { requestId: writeRequest.requestId, expectedApprovalDigest: writeRequest.approvalDigest! })).rejects.toThrow("E_DATABASE_SELF_APPROVAL_FORBIDDEN");

    await t.mutation(api.access.addMember, { workspaceId: seed.workspaceId, tokenIdentifier: "https://test-idp.example|reviewer", memberLabel: "Independent reviewer", role: "reviewer" });
    const reviewer = t.withIdentity({ subject: "reviewer", issuer: "https://test-idp.example", name: "reviewer" });
    expect((await reviewer.mutation(api.databaseTools.approveWrite, { requestId: writeRequest.requestId, expectedApprovalDigest: writeRequest.approvalDigest! })).marker).toBe("DATABASE_WRITE_APPROVED_AND_QUEUED");
    const listed = await t.query(api.databaseTools.list, { agentSpecId: seed.agentSpecId });
    expect(JSON.stringify(listed)).not.toContain("vault:agent-oven/database/operations");
  });

  test("rejects raw credentials, arbitrary SQL, and out-of-scope namespaces", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    await expect(t.mutation(api.databaseTools.configureConnection, { agentSpecId: seed.agentSpecId, engine: "postgresql", label: "Unsafe", endpointRef: "postgres://user:password@db.example/app", secretRef: "env:DATABASE_PASSWORD", allowedNamespaces: ["operations"] })).rejects.toThrow("E_DATABASE_CREDENTIAL_IN_REF");
    const connection = await t.mutation(api.databaseTools.configureConnection, { agentSpecId: seed.agentSpecId, engine: "postgresql", label: "Safe", endpointRef: "env:DATABASE_ENDPOINT", secretRef: "env:DATABASE_PASSWORD", allowedNamespaces: ["operations"] });
    await expect(t.mutation(api.databaseTools.registerOperation, { connectionId: connection.connectionId, operationKey: "unsafe", label: "Unsafe", mode: "read", executionKind: "parameterized", target: "SELECT * FROM users", parameterNames: [] })).rejects.toThrow("E_ARBITRARY_SQL_FORBIDDEN");
    await expect(t.mutation(api.databaseTools.registerOperation, { connectionId: connection.connectionId, operationKey: "finance", label: "Finance", mode: "read", executionKind: "view", target: "finance.ledger", parameterNames: [] })).rejects.toThrow("E_DATABASE_NAMESPACE_NOT_ALLOWED");
  });
});
