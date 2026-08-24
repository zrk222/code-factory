import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import schema from "./schema";

const modules = import.meta.glob("./**/*.ts");
const issuer = "https://idp.example";
const identity = (subject: string) => ({ subject, issuer, name: subject });
const tokenIdentifier = (subject: string) => `${issuer}|${subject}`;

async function fixture() {
  const t = convexTest(schema, modules);
  const now = Date.now();
  const ids = await t.run(async (ctx) => {
    const workspaceA = await ctx.db.insert("workspaces", { slug: "tenant-a", name: "Tenant A", plan: "pilot", createdAt: now });
    const workspaceB = await ctx.db.insert("workspaces", { slug: "tenant-b", name: "Tenant B", plan: "pilot", createdAt: now });
    const specB = await ctx.db.insert("agentSpecs", {
      workspaceId: workspaceB,
      name: "Tenant B agent",
      repository: "tenant-b/private",
      providerProfile: "balanced",
      memoryMode: "run-only",
      authorityMode: "read-only",
      hardBudgetCents: 100,
      validators: ["Test suite"],
      version: 1,
      status: "active",
      updatedAt: now,
    });
    return { workspaceA, workspaceB, specB };
  });
  return { t, owner: t.withIdentity(identity("owner-a")), viewer: t.withIdentity(identity("viewer-a")), attacker: t.withIdentity(identity("attacker-b")), ...ids };
}

async function counts(t: ReturnType<typeof convexTest>) {
  return t.run(async (ctx) => ({
    memberships: (await ctx.db.query("workspaceMemberships").collect()).length,
    receipts: (await ctx.db.query("receipts").collect()).length,
    audits: (await ctx.db.query("auditEvents").collect()).length,
  }));
}

describe("authenticated workspace isolation", () => {
  test("creates a separate tenant-scoped starter workspace for each authenticated user", async () => {
    const t = convexTest(schema, modules);
    const first = t.withIdentity(identity("onboarding-one"));
    const second = t.withIdentity(identity("onboarding-two"));
    const firstSeed = await first.mutation(api.seed.ensureDemo, {});
    const firstAgain = await first.mutation(api.seed.ensureDemo, {});
    const secondSeed = await second.mutation(api.seed.ensureDemo, {});
    expect(firstAgain.workspaceId).toBe(firstSeed.workspaceId);
    expect(secondSeed.workspaceId).not.toBe(firstSeed.workspaceId);
    expect((await first.query(api.access.myWorkspaces, {})).workspaces).toHaveLength(1);
    expect((await second.query(api.access.myWorkspaces, {})).workspaces).toHaveLength(1);
    await expect(first.query(api.access.readAgentSpec, { workspaceId: secondSeed.workspaceId, agentSpecId: secondSeed.agentSpecId! })).rejects.toThrow("E_WORKSPACE_ACCESS_DENIED");
  });

  test("requires authentication and bootstraps exactly one owner", async () => {
    const { t, owner, workspaceA } = await fixture();
    const before = await counts(t);
    await expect(t.mutation(api.access.bootstrapOwner, { workspaceId: workspaceA, memberLabel: "Anonymous" })).rejects.toThrow("E_AUTH_REQUIRED");
    expect(await counts(t)).toEqual(before);
    const result = await owner.mutation(api.access.bootstrapOwner, { workspaceId: workspaceA, memberLabel: "Primary owner" });
    expect(result).toMatchObject({ marker: "WORKSPACE_OWNER_BOOTSTRAPPED", principalMarker: "IDENTITY_PRINCIPAL_DERIVED", evidenceMarker: "IDENTITY_EVIDENCE_REDACTED" });
    expect(await counts(t)).toEqual({ memberships: 1, receipts: 1, audits: 1 });
    await expect(owner.mutation(api.access.bootstrapOwner, { workspaceId: workspaceA, memberLabel: "Again" })).rejects.toThrow("E_BOOTSTRAP_CLOSED");
  });

  test("rejects non-members and cross-workspace resources without writes", async () => {
    const { t, owner, attacker, workspaceA, specB } = await fixture();
    await owner.mutation(api.access.bootstrapOwner, { workspaceId: workspaceA, memberLabel: "Primary owner" });
    const before = await counts(t);
    await expect(attacker.query(api.access.myAccess, { workspaceId: workspaceA })).rejects.toThrow("E_WORKSPACE_ACCESS_DENIED");
    await expect(owner.query(api.access.readAgentSpec, { workspaceId: workspaceA, agentSpecId: specB })).rejects.toThrow("E_CROSS_TENANT_RESOURCE");
    expect(await counts(t)).toEqual(before);
  });

  test("adds a bounded member and explains only sanitized access state", async () => {
    const { owner, viewer, workspaceA } = await fixture();
    await owner.mutation(api.access.bootstrapOwner, { workspaceId: workspaceA, memberLabel: "Primary owner" });
    const added = await owner.mutation(api.access.addMember, {
      workspaceId: workspaceA,
      tokenIdentifier: tokenIdentifier("viewer-a"),
      memberLabel: "Security reviewer",
      role: "viewer",
    });
    expect(added).toMatchObject({ marker: "WORKSPACE_MEMBER_ADDED", evidenceMarker: "IDENTITY_EVIDENCE_REDACTED" });
    const access = await viewer.query(api.access.myAccess, { workspaceId: workspaceA });
    expect(access).toEqual({
      marker: "WORKSPACE_ACCESS_EXPLAINED",
      principalMarker: "IDENTITY_PRINCIPAL_DERIVED",
      workspaceId: workspaceA,
      memberLabel: "Security reviewer",
      role: "viewer",
      status: "active",
    });
    expect(JSON.stringify(access)).not.toContain(tokenIdentifier("viewer-a"));
  });

  test("keeps membership administration owner-only and blocks owner assignment", async () => {
    const { t, owner, viewer, workspaceA } = await fixture();
    await owner.mutation(api.access.bootstrapOwner, { workspaceId: workspaceA, memberLabel: "Primary owner" });
    const added = await owner.mutation(api.access.addMember, { workspaceId: workspaceA, tokenIdentifier: tokenIdentifier("viewer-a"), memberLabel: "Viewer", role: "viewer" });
    const before = await counts(t);
    await expect(viewer.mutation(api.access.addMember, { workspaceId: workspaceA, tokenIdentifier: tokenIdentifier("third"), memberLabel: "Third", role: "operator" })).rejects.toThrow("E_ROLE_FORBIDDEN");
    await expect(viewer.mutation(api.access.revokeMember, { membershipId: added.membershipId, reason: "Unauthorized" })).rejects.toThrow("E_ROLE_FORBIDDEN");
    await expect(owner.mutation(api.access.addMember, { workspaceId: workspaceA, tokenIdentifier: tokenIdentifier("second-owner"), memberLabel: "Second owner", role: "owner" })).rejects.toThrow("E_OWNER_ASSIGNMENT_FORBIDDEN");
    expect(await counts(t)).toEqual(before);
  });

  test("revokes a member, denies later access, and preserves the last owner", async () => {
    const { t, owner, viewer, workspaceA } = await fixture();
    const bootstrapped = await owner.mutation(api.access.bootstrapOwner, { workspaceId: workspaceA, memberLabel: "Primary owner" });
    const added = await owner.mutation(api.access.addMember, { workspaceId: workspaceA, tokenIdentifier: tokenIdentifier("viewer-a"), memberLabel: "Viewer", role: "viewer" });
    const revoked = await owner.mutation(api.access.revokeMember, { membershipId: added.membershipId, reason: "Pilot access ended." });
    expect(revoked).toMatchObject({ marker: "WORKSPACE_MEMBER_REVOKED", evidenceMarker: "IDENTITY_EVIDENCE_REDACTED" });
    await expect(viewer.query(api.access.myAccess, { workspaceId: workspaceA })).rejects.toThrow("E_WORKSPACE_ACCESS_DENIED");
    const before = await counts(t);
    await expect(owner.mutation(api.access.revokeMember, { membershipId: bootstrapped.membershipId, reason: "Would orphan workspace." })).rejects.toThrow("E_LAST_OWNER_REQUIRED");
    expect(await counts(t)).toEqual(before);
    const evidence = await t.run(async (ctx) => ({ receipts: await ctx.db.query("receipts").collect(), audits: await ctx.db.query("auditEvents").collect() }));
    expect(evidence.receipts.filter((receipt) => receipt.type === "identity-access")).toHaveLength(3);
    expect(JSON.stringify(evidence)).not.toMatch(/owner-a|viewer-a|https:\/\/idp\.example/i);
  });
});
