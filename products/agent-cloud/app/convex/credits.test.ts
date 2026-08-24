import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";

const blueprintArgs = { templateId: "books-close-assistant", name: "Books Close Assistant", mode: "guided" as const, triggerKind: "manual" as const, triggerLabel: "Start close", steps: [{ id: "reconcile", label: "Reconcile evidence", kind: "validate" as const, humanGate: true }], memoryPolicy: "governed" as const, modelPolicy: "highest-quality" as const, authorityPolicy: "approval-required" as const, evidenceLevel: "full" as const, hardBudgetCents: 4500 };

describe("platform credit ledger", () => {
  test("uses published template pricing and reconciles unused credits atomically", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    const blueprint = await t.mutation(api.blueprints.save, { agentSpecId: seed.agentSpecId, ...blueprintArgs });
    const quote = await t.query(api.credits.quote, { blueprintId: blueprint.blueprintId });
    expect(quote).toMatchObject({ pricingMode: "fixed-template", total: 120 });
    const reservation = await t.mutation(api.credits.reserveBlueprint, { blueprintId: blueprint.blueprintId, idempotencyKey: "books-v1" });
    expect(reservation).toMatchObject({ quotedCredits: 120, availableCredits: 380 });
    const replay = await t.mutation(api.credits.reserveBlueprint, { blueprintId: blueprint.blueprintId, idempotencyKey: "books-v1" });
    expect(replay.marker).toBe("CREDIT_RESERVATION_REPLAYED");
    const settled = await t.mutation(api.credits.settle, { reservationId: reservation.reservationId, actualCredits: 100 });
    expect(settled).toMatchObject({ actualCredits: 100, releasedCredits: 20, availableCredits: 400 });
    const status = await t.query(api.credits.status, { workspaceId: seed.workspaceId });
    expect(status.account).toMatchObject({ availableCredits: 400, reservedCredits: 0, spentCredits: 100 });
    expect(status.inferenceLedgerMarker).toBe("BYOK_INFERENCE_SEPARATE");
  });

  test("never permits overspend or actual credits above reservation", async () => {
    const t = authenticatedTest();
    const seed = await t.mutation(api.seed.ensureDemo, {});
    if (!seed.agentSpecId) throw new Error("missing spec");
    const blueprint = await t.mutation(api.blueprints.save, { agentSpecId: seed.agentSpecId, ...blueprintArgs });
    const reservation = await t.mutation(api.credits.reserveBlueprint, { blueprintId: blueprint.blueprintId, idempotencyKey: "bounded" });
    await expect(t.mutation(api.credits.settle, { reservationId: reservation.reservationId, actualCredits: 121 })).rejects.toThrow();
  });
});
