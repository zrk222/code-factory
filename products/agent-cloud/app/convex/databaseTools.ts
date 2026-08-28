import { v } from "convex/values";
import { internalMutation, mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";
import { assertText, receiptFingerprint, validateSecretReference } from "./domain";

const engine = v.union(v.literal("postgresql"), v.literal("mysql"), v.literal("sql-server"), v.literal("mongodb"), v.literal("warehouse"));
const mode = v.union(v.literal("read"), v.literal("write"));
const executionKind = v.union(v.literal("view"), v.literal("parameterized"), v.literal("stored-procedure"));

function safeRef(value: string, name: string) {
  const ref = assertText(value, name, 500);
  if (/\/\/[^/\s]+:[^/@\s]+@/i.test(ref) || /[?&](?:token|key|secret|password)=/i.test(ref)) throw new Error("E_DATABASE_CREDENTIAL_IN_REF");
  return ref;
}

function identifier(value: string, name: string) {
  const normalized = assertText(value, name, 160);
  if (!/^[A-Za-z_][A-Za-z0-9_.:-]*$/.test(normalized) || /\b(?:select|insert|update|delete|drop|alter|create|grant|revoke|exec|call)\b/i.test(normalized)) throw new Error("E_ARBITRARY_SQL_FORBIDDEN");
  return normalized;
}

/** Configures a remote database through opaque endpoint and secret references only. */
export const configureConnection = mutation({
  args: { agentSpecId: v.id("agentSpecs"), engine, label: v.string(), endpointRef: v.string(), secretRef: v.string(), allowedNamespaces: v.array(v.string()) },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "admin");
    if (args.allowedNamespaces.length < 1 || args.allowedNamespaces.length > 50) throw new Error("E_DATABASE_NAMESPACE_ALLOWLIST_REQUIRED");
    const record = { workspaceId: spec.workspaceId, agentSpecId: spec._id, engine: args.engine, label: assertText(args.label, "database_label", 120), endpointRef: safeRef(args.endpointRef, "database_endpoint_ref"), secretRef: validateSecretReference(args.secretRef), allowedNamespaces: [...new Set(args.allowedNamespaces.map((item) => identifier(item, "database_namespace")))], status: "setup-required" as const, validationDigest: undefined, updatedAt: Date.now() };
    const existing = await ctx.db.query("databaseToolConnections").withIndex("by_agent", (q) => q.eq("agentSpecId", spec._id)).unique();
    const connectionId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("databaseToolConnections", record);
    return { marker: "REMOTE_DATABASE_CONNECTION_CONFIGURED" as const, connectionId, status: "setup-required" as const };
  },
});

/** Registers a named view, parameterized operation, or stored procedure; raw SQL is never accepted. */
export const registerOperation = mutation({
  args: { connectionId: v.id("databaseToolConnections"), operationKey: v.string(), label: v.string(), mode, executionKind, target: v.string(), parameterNames: v.array(v.string()) },
  handler: async (ctx, args) => {
    const connection = await ctx.db.get(args.connectionId);
    if (!connection) throw new Error("E_DATABASE_CONNECTION_NOT_FOUND");
    await requireWorkspaceRole(ctx, connection.workspaceId, "admin");
    if (args.mode === "write" && args.executionKind === "view") throw new Error("E_DATABASE_WRITE_KIND_FORBIDDEN");
    const operationKey = identifier(args.operationKey, "operation_key");
    const target = identifier(args.target, "operation_target");
    const namespace = target.split(/[.:-]/)[0];
    if (!connection.allowedNamespaces.includes(namespace)) throw new Error("E_DATABASE_NAMESPACE_NOT_ALLOWED");
    if (args.parameterNames.length > 50) throw new Error("E_DATABASE_PARAMETER_LIMIT");
    const record = { workspaceId: connection.workspaceId, agentSpecId: connection.agentSpecId, connectionId: connection._id, operationKey, label: assertText(args.label, "operation_label", 120), mode: args.mode, executionKind: args.executionKind, target, parameterNames: [...new Set(args.parameterNames.map((item) => identifier(item, "parameter_name")))], approvalRequired: args.mode === "write", status: "draft" as const, updatedAt: Date.now() };
    const existing = await ctx.db.query("databaseToolOperations").withIndex("by_connection_key", (q) => q.eq("connectionId", connection._id).eq("operationKey", operationKey)).unique();
    const operationId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("databaseToolOperations", record);
    return { marker: "REMOTE_DATABASE_OPERATION_DRAFTED" as const, operationId, approvalRequired: record.approvalRequired };
  },
});

/** Publishes one reviewed database operation into the assembler allowlist. */
export const publishOperation = mutation({
  args: { operationId: v.id("databaseToolOperations") },
  handler: async (ctx, args) => {
    const operation = await ctx.db.get(args.operationId);
    if (!operation) throw new Error("E_DATABASE_OPERATION_NOT_FOUND");
    await requireWorkspaceRole(ctx, operation.workspaceId, "admin");
    await ctx.db.patch(operation._id, { status: "published", updatedAt: Date.now() });
    return { marker: "REMOTE_DATABASE_OPERATION_PUBLISHED" as const, operationId: operation._id };
  },
});

/** Queues a read or opens a digest-bound approval for a write. */
export const requestOperation = mutation({
  args: { operationId: v.id("databaseToolOperations"), parametersRef: v.string(), parametersDigest: v.string() },
  handler: async (ctx, args) => {
    const operation = await ctx.db.get(args.operationId);
    if (!operation || operation.status !== "published") throw new Error("E_DATABASE_OPERATION_NOT_ALLOWED");
    const authorized = await requireWorkspaceRole(ctx, operation.workspaceId, "operator");
    const connection = await ctx.db.get(operation.connectionId);
    if (!connection || connection.status !== "active") throw new Error("E_DATABASE_CONNECTION_NOT_ACTIVE");
    const parametersDigest = assertText(args.parametersDigest, "parameters_digest", 120);
    const approvalDigest = receiptFingerprint([String(operation._id), parametersDigest, operation.mode]);
    const status = operation.mode === "write" ? "awaiting-approval" as const : "queued" as const;
    const requestId = await ctx.db.insert("databaseOperationRequests", { workspaceId: operation.workspaceId, agentSpecId: operation.agentSpecId, operationId: operation._id, parametersDigest, parametersRef: safeRef(args.parametersRef, "parameters_ref"), requestedBy: authorized.tokenIdentifier, status, approvalDigest: operation.mode === "write" ? approvalDigest : undefined, createdAt: Date.now() });
    return { marker: operation.mode === "write" ? "DATABASE_WRITE_AWAITING_APPROVAL" as const : "DATABASE_READ_QUEUED" as const, requestId, approvalDigest: operation.mode === "write" ? approvalDigest : undefined };
  },
});

/** Approves the exact write digest using a distinct authenticated reviewer. */
export const approveWrite = mutation({
  args: { requestId: v.id("databaseOperationRequests"), expectedApprovalDigest: v.string() },
  handler: async (ctx, args) => {
    const request = await ctx.db.get(args.requestId);
    if (!request) throw new Error("E_DATABASE_REQUEST_NOT_FOUND");
    const authorized = await requireWorkspaceRole(ctx, request.workspaceId, "reviewer");
    if (request.status !== "awaiting-approval" || request.approvalDigest !== args.expectedApprovalDigest) throw new Error("E_DATABASE_APPROVAL_MISMATCH");
    if (authorized.tokenIdentifier === request.requestedBy) throw new Error("E_DATABASE_SELF_APPROVAL_FORBIDDEN");
    await ctx.db.patch(request._id, { status: "queued", approvedBy: authorized.tokenIdentifier, decidedAt: Date.now() });
    return { marker: "DATABASE_WRITE_APPROVED_AND_QUEUED" as const, requestId: request._id };
  },
});

/** Lists only connection metadata, allowed operations, and operation status; secrets are omitted. */
export const list = query({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const spec = await ctx.db.get(args.agentSpecId);
    if (!spec) throw new Error("E_AGENT_SPEC_NOT_FOUND");
    await requireWorkspaceRole(ctx, spec.workspaceId, "viewer");
    const connection = await ctx.db.query("databaseToolConnections").withIndex("by_agent", (q) => q.eq("agentSpecId", spec._id)).unique();
    if (!connection) return { connection: null, operations: [], requests: [] };
    const operations = await ctx.db.query("databaseToolOperations").withIndex("by_connection_key", (q) => q.eq("connectionId", connection._id)).collect();
    const requests = await ctx.db.query("databaseOperationRequests").withIndex("by_agent_created", (q) => q.eq("agentSpecId", spec._id)).order("desc").take(20);
    const { secretRef: _secretRef, ...safeConnection } = connection;
    return { connection: safeConnection, operations, requests: requests.map(({ requestedBy: _requestedBy, approvedBy: _approvedBy, approvalDigest: _approvalDigest, parametersRef: _parametersRef, ...request }) => request) };
  },
});

/** Activates a database binding only after a trusted adapter validates it. */
export const activateConnection = internalMutation({
  args: { connectionId: v.id("databaseToolConnections"), validationDigest: v.string() },
  handler: async (ctx, args) => { const connection = await ctx.db.get(args.connectionId); if (!connection || connection.status !== "setup-required") throw new Error("E_DATABASE_CONNECTION_NOT_ACTIVATABLE"); const validationDigest = assertText(args.validationDigest, "validation_digest", 120); await ctx.db.patch(connection._id, { status: "active", validationDigest, updatedAt: Date.now() }); return { marker: "REMOTE_DATABASE_CONNECTION_ACTIVE" as const, connectionId: connection._id }; },
});

/** Completes only queued work after the trusted database adapter returns a digest. */
export const completeOperation = internalMutation({
  args: { requestId: v.id("databaseOperationRequests"), succeeded: v.boolean(), resultDigest: v.optional(v.string()), failureCode: v.optional(v.string()) },
  handler: async (ctx, args) => { const request = await ctx.db.get(args.requestId); if (!request || request.status !== "queued") throw new Error("E_DATABASE_REQUEST_NOT_QUEUED"); if (args.succeeded && !args.resultDigest) throw new Error("E_DATABASE_RESULT_DIGEST_REQUIRED"); const now = Date.now(); await ctx.db.patch(request._id, { status: args.succeeded ? "succeeded" : "failed", resultDigest: args.resultDigest ? assertText(args.resultDigest, "result_digest", 120) : undefined, failureCode: args.failureCode ? assertText(args.failureCode, "failure_code", 120) : undefined, completedAt: now }); return { marker: args.succeeded ? "REMOTE_DATABASE_OPERATION_COMPLETED" as const : "REMOTE_DATABASE_OPERATION_FAILED" as const, requestId: request._id }; },
});
