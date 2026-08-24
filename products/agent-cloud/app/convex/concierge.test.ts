import { describe, expect, test } from "vitest";
import { api } from "./_generated/api";
import { authenticatedTest } from "./testIdentity.testSupport";
import { scoreLead } from "./conciergeDomain";

async function fixture() {
  const t = authenticatedTest();
  const seed = await t.mutation(api.seed.ensureDemo, {});
  if (!seed.agentSpecId) throw new Error("missing agent");
  const profile = await t.mutation(api.concierge.saveProfile, { agentSpecId: seed.agentSpecId, serviceName: "Emergency plumbing", serviceArea: "Toronto", appointmentDurationMinutes: 90, minimumLeadScore: 80, modeledJobValueCents: 32500 });
  return { t, seed, profile };
}

describe("Booked Job Concierge", () => {
  test("scores declared facts deterministically", () => {
    expect(scoreLead({ serviceMatch: true, areaMatch: true, urgency: "urgent", contactReady: true, minimumLeadScore: 80 })).toEqual({ score: 100, classification: "qualified", reasons: ["service-matched", "service-area-matched", "contact-ready", "urgency-urgent"] });
    expect(scoreLead({ serviceMatch: true, areaMatch: false, urgency: "urgent", contactReady: true, minimumLeadScore: 80 })).toMatchObject({ score: 30, classification: "rejected" });
  });

  test("rejects missing consent before any lead or outcome write", async () => {
    const { t, seed } = await fixture();
    const before = await t.run(async (ctx) => ({ leads: (await ctx.db.query("conciergeLeads").collect()).length, outcomes: (await ctx.db.query("conciergeOutcomeEvents").collect()).length }));
    await expect(t.mutation(api.concierge.submitLead, { agentSpecId: seed.agentSpecId!, leadAlias: "Sample lead", serviceRequested: "Burst pipe", areaLabel: "Toronto", serviceMatch: true, areaMatch: true, urgency: "urgent", contactReady: true, contactConsent: false })).rejects.toThrow("E_CONTACT_CONSENT_REQUIRED");
    const after = await t.run(async (ctx) => ({ leads: (await ctx.db.query("conciergeLeads").collect()).length, outcomes: (await ctx.db.query("conciergeOutcomeEvents").collect()).length }));
    expect(after).toEqual(before);
  });

  test("runs one complete sandbox booking and keeps modeled value separate from observed revenue", async () => {
    const { t, seed } = await fixture();
    const lead = await t.mutation(api.concierge.submitLead, { agentSpecId: seed.agentSpecId!, leadAlias: "Sample lead", serviceRequested: "Burst pipe", areaLabel: "Toronto", serviceMatch: true, areaMatch: true, urgency: "urgent", contactReady: true, contactConsent: true });
    expect(lead).toMatchObject({ marker: "CONCIERGE_LEAD_SCORED", score: 100, classification: "qualified" });
    const requested = await t.mutation(api.concierge.requestBooking, { leadId: lead.leadId, environment: "sandbox", proposedStartAt: Date.now() + 3600000 });
    const confirmed = await t.mutation(api.concierge.approveBooking, { approvalId: requested.approvalId, slotDigest: requested.slotDigest, approve: true });
    expect(confirmed).toMatchObject({ marker: "SANDBOX_BOOKING_CONFIRMED", evidenceClass: "modeled" });
    await expect(t.mutation(api.concierge.approveBooking, { approvalId: requested.approvalId, slotDigest: requested.slotDigest, approve: true })).rejects.toThrow("E_BOOKING_APPROVAL_NOT_PENDING");
    await t.mutation(api.concierge.recordOutcome, { bookingId: confirmed.bookingId!, type: "attended" });
    await t.mutation(api.concierge.recordOutcome, { bookingId: confirmed.bookingId!, type: "revenue-confirmed", valueCents: 29500 });
    const overview = await t.query(api.concierge.overview, { agentSpecId: seed.agentSpecId! });
    expect(overview.metrics).toMatchObject({ leads: 1, qualified: 1, bookings: 1, attended: 1, modeledPipelineValueCents: 32500, observedRevenueCents: 29500 });
    expect(overview.leads[0].decisionReasons).toContain("service-area-matched");
  });

  test("keeps production fail-closed and rejects raw adapter credentials", async () => {
    const { t, seed } = await fixture();
    await expect(t.mutation(api.concierge.configureAdapter, { agentSpecId: seed.agentSpecId!, kind: "billing", provider: "stripe", accountLabel: "Production", secretRef: "sk_live_not_allowed" })).rejects.toThrow("E_RAW_SECRET_FORBIDDEN");
    const configured = await t.mutation(api.concierge.configureAdapter, { agentSpecId: seed.agentSpecId!, kind: "billing", provider: "stripe", accountLabel: "Production", secretRef: "vault:agent-oven/stripe" });
    expect(configured).toMatchObject({ status: "setup-required", credentialMarker: "OPAQUE_SECRET_REFERENCE_ONLY" });
    const lead = await t.mutation(api.concierge.submitLead, { agentSpecId: seed.agentSpecId!, leadAlias: "Production lead", serviceRequested: "Burst pipe", areaLabel: "Toronto", serviceMatch: true, areaMatch: true, urgency: "urgent", contactReady: true, contactConsent: true });
    const before = await t.run(async (ctx) => ({ approvals: (await ctx.db.query("conciergeBookingApprovals").collect()).length, bookings: (await ctx.db.query("conciergeBookings").collect()).length, credits: (await ctx.db.query("creditTransactions").collect()).length }));
    await expect(t.mutation(api.concierge.requestBooking, { leadId: lead.leadId, environment: "production", proposedStartAt: Date.now() + 3600000 })).rejects.toThrow("E_CONCIERGE_ADAPTERS_NOT_READY");
    const after = await t.run(async (ctx) => ({ approvals: (await ctx.db.query("conciergeBookingApprovals").collect()).length, bookings: (await ctx.db.query("conciergeBookings").collect()).length, credits: (await ctx.db.query("creditTransactions").collect()).length }));
    expect(after).toEqual(before);
  });
});
