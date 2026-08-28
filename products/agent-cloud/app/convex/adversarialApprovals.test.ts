import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";

async function seeded() {
  const t = authenticatedTest();
  const seed = await t.mutation(api.seed.ensureDemo, {});
  if (!seed.agentSpecId) throw new Error("seed did not create an AgentSpec");
  return { t, agentSpecId: seed.agentSpecId };
}

describe("adversarial approval integration", () => {
  test("records a human-required review before a merge decision", async () => {
    const { t, agentSpecId } = await seeded();
    const launched = await t.mutation(api.control.launchRun, { agentSpecId, branch: "feature/boundary", commitSha: "a".repeat(40), estimatedCostCents: 90, taskKind: "merge-proposal" });
    const detail = await t.query(api.control.runDetail, { runId: launched.runId });
    expect(launched).toMatchObject({ reviewMarker: "ADVERSARIAL_APPROVAL_RECORDED", reviewVerdict: "human-required" });
    expect(detail?.approval?.status).toBe("pending");
    expect(detail?.adversarialReview).toMatchObject({ actionClass: "code-change", environment: "production", verdict: "human-required", policyVersion: "adversarial-approval.v1" });
  });

  test("auto-approves bounded evidence analysis and records an immutable receipt", async () => {
    const { t, agentSpecId } = await seeded();
    const launched = await t.mutation(api.control.launchRun, { agentSpecId, branch: "analysis/receipts", commitSha: "b".repeat(40), estimatedCostCents: 50, taskKind: "analyze-evidence" });
    const detail = await t.query(api.control.runDetail, { runId: launched.runId });
    expect(launched.reviewVerdict).toBe("auto-approved");
    expect(detail?.run.status).toBe("approved");
    expect(detail?.approval?.status).toBe("approved");
    expect(detail?.receipts.some((receipt) => receipt.event === "approval.adversarial.auto-approved")).toBe(true);
  });

  test("binds task class and environment into distinct action digests", async () => {
    const { t, agentSpecId } = await seeded();
    const common = { agentSpecId, branch: "feature/same-content", commitSha: "c".repeat(40), estimatedCostCents: 50 };
    const analysis = await t.mutation(api.control.launchRun, { ...common, taskKind: "analyze-evidence" });
    const merge = await t.mutation(api.control.launchRun, { ...common, taskKind: "merge-proposal" });
    const analysisDetail = await t.query(api.control.runDetail, { runId: analysis.runId });
    const mergeDetail = await t.query(api.control.runDetail, { runId: merge.runId });
    expect(analysisDetail?.run.actionDigest).not.toBe(mergeDetail?.run.actionDigest);
    expect(mergeDetail?.adversarialReview?.verdict).toBe("human-required");
  });
});
