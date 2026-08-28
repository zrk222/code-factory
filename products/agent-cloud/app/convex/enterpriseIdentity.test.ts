import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";

describe("enterprise organization and directory boundary", () => {
  test("creates an organization, stores only an opaque directory reference, and provisions idempotently", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    const organization = await t.mutation(api.enterpriseIdentity.createOrganization, { workspaceId: seed.workspaceId, slug: "acme", name: "Acme", ownerLabel: "Security owner" });
    expect(organization.marker).toBe("ENTERPRISE_ORGANIZATION_CREATED");
    const directory = await t.mutation(api.enterpriseIdentity.configureDirectory, { organizationId: organization.organizationId, workspaceId: seed.workspaceId, protocol: "scim-2.0", issuer: "https://id.acme.example", tenantKey: "acme-production", secretRef: "vault:agent-oven/acme-scim", defaultWorkspaceRole: "operator" });
    expect(directory).toMatchObject({ marker: "ENTERPRISE_DIRECTORY_CONFIGURED", status: "setup-required", credentialMarker: "OPAQUE_SECRET_REFERENCE_ONLY" });
    const args = { organizationId: organization.organizationId, directoryConnectionId: directory.directoryConnectionId, workspaceId: seed.workspaceId, externalId: "user-42", tokenIdentifier: "https://id.acme.example|user-42", memberLabel: "Automation operator" };
    const first = await t.mutation(api.enterpriseIdentity.provisionWorkspaceMember, args);
    const replay = await t.mutation(api.enterpriseIdentity.provisionWorkspaceMember, args);
    expect(first.idempotent).toBe(false);
    expect(replay).toEqual({ marker: "ENTERPRISE_MEMBER_PROVISIONED", membershipId: first.membershipId, idempotent: true });
    const stored = await t.run(async (ctx) => ctx.db.get(first.membershipId));
    expect(stored).toMatchObject({ role: "operator", directoryExternalId: "user-42", status: "active" });
  });

  test("blocks cross-organization directory use and raw secrets", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    const organization = await t.mutation(api.enterpriseIdentity.createOrganization, { workspaceId: seed.workspaceId, slug: "safe-org", name: "Safe Org", ownerLabel: "Owner" });
    await expect(t.mutation(api.enterpriseIdentity.configureDirectory, { organizationId: organization.organizationId, workspaceId: seed.workspaceId, protocol: "oidc", issuer: "https://id.safe.example", tenantKey: "safe", secretRef: "sk-raw-secret", defaultWorkspaceRole: "viewer" })).rejects.toThrow("E_RAW_SECRET_FORBIDDEN");
    const otherWorkspaceId = await t.run(async (ctx) => ctx.db.insert("workspaces", { slug: "other", name: "Other", plan: "pilot", createdAt: Date.now() }));
    await expect(t.mutation(api.enterpriseIdentity.configureDirectory, { organizationId: organization.organizationId, workspaceId: otherWorkspaceId, protocol: "oidc", issuer: "https://id.safe.example", tenantKey: "safe", secretRef: "env:SAFE_OIDC", defaultWorkspaceRole: "viewer" })).rejects.toThrow("E_CROSS_ORGANIZATION_WORKSPACE");
  });
});
