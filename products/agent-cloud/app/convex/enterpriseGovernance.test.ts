import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";

async function enterpriseFixture() {
  const t = authenticatedTest();
  const seed = await t.mutation(api.seed.ensureDemo, {});
  const organization = await t.mutation(api.enterpriseIdentity.createOrganization, { workspaceId: seed.workspaceId, slug: `org-${Date.now()}`, name: "Regulated Org", ownerLabel: "Owner" });
  return { t, seed, organization };
}

describe("enterprise governance controls", () => {
  test("enforces separate backup failure domain and stores only a key reference", async () => {
    const { t, seed, organization } = await enterpriseFixture();
    await expect(t.mutation(api.enterpriseGovernance.configurePolicy, { organizationId: organization.organizationId, workspaceId: seed.workspaceId, residencyRegion: "ca-central", backupRegion: "ca-central", kmsKeyRef: "vault:keys/customer", retentionDays: 365, rtoMinutes: 60, rpoMinutes: 15, enforce: true })).rejects.toThrow("E_BACKUP_FAILURE_DOMAIN_NOT_SEPARATE");
    const result = await t.mutation(api.enterpriseGovernance.configurePolicy, { organizationId: organization.organizationId, workspaceId: seed.workspaceId, residencyRegion: "ca-central", backupRegion: "us-east", kmsKeyRef: "vault:keys/customer", retentionDays: 365, rtoMinutes: 60, rpoMinutes: 15, enforce: true });
    expect(result).toMatchObject({ marker: "ENTERPRISE_GOVERNANCE_POLICY_CONFIGURED", status: "enforced", keyMarker: "CUSTOMER_MANAGED_KEY_REFERENCE_ONLY" });
  });

  test("legal hold blocks matching deletion until explicitly released", async () => {
    const { t, seed, organization } = await enterpriseFixture();
    const hold = await t.mutation(api.enterpriseGovernance.placeLegalHold, { organizationId: organization.organizationId, workspaceId: seed.workspaceId, scope: "subject", scopeKey: "customer-42", reason: "Litigation preservation" });
    const blocked = await t.mutation(api.enterpriseGovernance.requestDeletion, { organizationId: organization.organizationId, workspaceId: seed.workspaceId, scope: "subject", scopeKey: "customer-42", reason: "Data subject request" });
    expect(blocked.status).toBe("blocked-by-legal-hold");
    await t.mutation(api.enterpriseGovernance.releaseLegalHold, { organizationId: organization.organizationId, holdId: hold.holdId });
    const admitted = await t.mutation(api.enterpriseGovernance.requestDeletion, { organizationId: organization.organizationId, workspaceId: seed.workspaceId, scope: "subject", scopeKey: "customer-42", reason: "Data subject request" });
    expect(admitted.status).toBe("approved-for-execution");
  });
});
