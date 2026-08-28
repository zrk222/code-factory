import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import { consumeAdmission } from "./enterpriseSecurity";
import { authenticatedTest } from "./testIdentity.testSupport";

describe("enterprise admission control", () => {
  test("enforces an atomic window and rejects excess requests", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    const organization = await t.mutation(api.enterpriseIdentity.createOrganization, { workspaceId: seed.workspaceId, slug: `security-${Date.now()}`, name: "Security Org", ownerLabel: "Owner" });
    const configured = await t.mutation(api.enterpriseSecurity.configureAdmission, { organizationId: organization.organizationId, workspaceId: seed.workspaceId, maxRequests: 1, windowSeconds: 60, maxConcurrentRuns: 2, enforce: true });
    expect(configured).toMatchObject({ marker: "ENTERPRISE_ADMISSION_CONFIGURED", status: "enforced" });
    const first = await t.run((ctx) => consumeAdmission(ctx, seed.workspaceId, "execution.enqueue"));
    expect(first).toEqual({ marker: "REQUEST_ADMITTED", remaining: 0 });
    await expect(t.run((ctx) => consumeAdmission(ctx, seed.workspaceId, "execution.enqueue"))).rejects.toThrow("E_RATE_LIMIT_REACHED");
  });
});
