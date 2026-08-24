import { v } from "convex/values";
import type { Doc } from "./_generated/dataModel";
import type { Id } from "./_generated/dataModel";
import type { MutationCtx, QueryCtx } from "./_generated/server";
import { internalMutation, mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";
import { assertIntegerRange, assertText, receiptFingerprint, validateSecretReference } from "./domain";
import { scoreLead } from "./conciergeDomain";

const adapterKind = v.union(v.literal("calendar"), v.literal("messaging"), v.literal("billing"), v.literal("model"));
const urgency = v.union(v.literal("flexible"), v.literal("soon"), v.literal("urgent"));
const environment = v.union(v.literal("sandbox"), v.literal("production"));
const outcomeType = v.union(v.literal("attended"), v.literal("no-show"), v.literal("canceled"), v.literal("revenue-confirmed"));
const allowedProviders: Record<Doc<"conciergeAdapters">["kind"], readonly string[]> = {
  calendar: ["google-calendar", "microsoft-365", "calendly"],
  messaging: ["twilio", "email"],
  billing: ["stripe"],
  model: ["openai", "anthropic"],
};

async function agentFor(ctx: MutationCtx | QueryCtx, agentSpecId: Id<"agentSpecs">) {
  const agent = await ctx.db.get(agentSpecId);
  if (!agent) throw new Error("E_AGENT_SPEC_NOT_FOUND");
  return agent;
}

/** Saves the novice service contract without charging credits or invoking a provider. */
export const saveProfile = mutation({
  args: { agentSpecId: v.id("agentSpecs"), serviceName: v.string(), serviceArea: v.string(), appointmentDurationMinutes: v.number(), minimumLeadScore: v.number(), modeledJobValueCents: v.number() },
  handler: async (ctx, args) => {
    const agent = await agentFor(ctx, args.agentSpecId);
    await requireWorkspaceRole(ctx, agent.workspaceId, "admin");
    assertIntegerRange(args.appointmentDurationMinutes, "appointment_duration_minutes", 15, 480);
    assertIntegerRange(args.minimumLeadScore, "minimum_lead_score", 0, 100);
    assertIntegerRange(args.modeledJobValueCents, "modeled_job_value_cents", 0, 100000000);
    const existing = await ctx.db.query("conciergeProfiles").withIndex("by_agent", (q) => q.eq("agentSpecId", agent._id)).unique();
    const now = Date.now();
    const version = (existing?.version ?? 0) + 1;
    const record = { workspaceId: agent.workspaceId, agentSpecId: agent._id, serviceName: assertText(args.serviceName, "service_name", 160), serviceArea: assertText(args.serviceArea, "service_area", 240), appointmentDurationMinutes: args.appointmentDurationMinutes, minimumLeadScore: args.minimumLeadScore, modeledJobValueCents: args.modeledJobValueCents, approvalRequired: true as const, version, status: "sandbox-ready" as const, updatedAt: now };
    const profileId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("conciergeProfiles", record);
    const adapters = await ctx.db.query("conciergeAdapters").withIndex("by_agent_kind", (q) => q.eq("agentSpecId", agent._id)).collect();
    return { marker: "CONCIERGE_PROFILE_SAVED" as const, profileId, version, creditsCharged: 0, readiness: { sandbox: true, production: ["calendar", "messaging", "billing", "model"].every((kind) => adapters.some((item) => item.kind === kind && item.status === "active")) } };
  },
});

/** Stores production adapter metadata and an opaque secret reference only. */
export const configureAdapter = mutation({
  args: { agentSpecId: v.id("agentSpecs"), kind: adapterKind, provider: v.string(), accountLabel: v.string(), secretRef: v.string() },
  handler: async (ctx, args) => {
    const agent = await agentFor(ctx, args.agentSpecId);
    await requireWorkspaceRole(ctx, agent.workspaceId, "admin");
    const provider = assertText(args.provider, "adapter_provider", 80);
    if (!allowedProviders[args.kind].includes(provider)) throw new Error("E_CONCIERGE_PROVIDER_NOT_ALLOWED");
    const existing = await ctx.db.query("conciergeAdapters").withIndex("by_agent_kind", (q) => q.eq("agentSpecId", agent._id).eq("kind", args.kind)).unique();
    const record = { workspaceId: agent.workspaceId, agentSpecId: agent._id, kind: args.kind, provider, accountLabel: assertText(args.accountLabel, "account_label", 160), secretRef: validateSecretReference(args.secretRef), status: "setup-required" as const, validationDigest: undefined, updatedAt: Date.now() };
    const adapterId = existing ? (await ctx.db.patch(existing._id, record), existing._id) : await ctx.db.insert("conciergeAdapters", record);
    return { marker: "CONCIERGE_ADAPTER_CONFIGURED" as const, adapterId, status: "setup-required" as const, credentialMarker: "OPAQUE_SECRET_REFERENCE_ONLY" as const };
  },
});

/** Activates a binding only from the trusted adapter-validation plane. */
export const markAdapterActive = internalMutation({
  args: { adapterId: v.id("conciergeAdapters"), validationDigest: v.string() },
  handler: async (ctx, args) => {
    const adapter = await ctx.db.get(args.adapterId);
    if (!adapter || adapter.status !== "setup-required") throw new Error("E_CONCIERGE_ADAPTER_NOT_VALIDATABLE");
    const validationDigest = assertText(args.validationDigest, "validation_digest", 120);
    await ctx.db.patch(adapter._id, { status: "active", validationDigest, updatedAt: Date.now() });
    return { marker: "CONCIERGE_ADAPTER_ACTIVATED" as const, adapterId: adapter._id };
  },
});

/** Creates a secret-free lead after consent and deterministic qualification. */
export const submitLead = mutation({
  args: { agentSpecId: v.id("agentSpecs"), leadAlias: v.string(), serviceRequested: v.string(), areaLabel: v.string(), serviceMatch: v.boolean(), areaMatch: v.boolean(), urgency, contactReady: v.boolean(), contactConsent: v.boolean() },
  handler: async (ctx, args) => {
    const agent = await agentFor(ctx, args.agentSpecId);
    await requireWorkspaceRole(ctx, agent.workspaceId, "operator");
    if (!args.contactConsent) throw new Error("E_CONTACT_CONSENT_REQUIRED");
    const profile = await ctx.db.query("conciergeProfiles").withIndex("by_agent", (q) => q.eq("agentSpecId", agent._id)).unique();
    if (!profile) throw new Error("E_CONCIERGE_PROFILE_REQUIRED");
    const result = scoreLead({ serviceMatch: args.serviceMatch, areaMatch: args.areaMatch, urgency: args.urgency, contactReady: args.contactReady, minimumLeadScore: profile.minimumLeadScore });
    const now = Date.now();
    const leadId = await ctx.db.insert("conciergeLeads", { workspaceId: agent.workspaceId, agentSpecId: agent._id, leadAlias: assertText(args.leadAlias, "lead_alias", 80), serviceRequested: assertText(args.serviceRequested, "service_requested", 160), areaLabel: assertText(args.areaLabel, "area_label", 100), serviceMatch: args.serviceMatch, areaMatch: args.areaMatch, urgency: args.urgency, contactReady: args.contactReady, contactConsent: true, score: result.score, classification: result.classification, decisionReasons: result.reasons, status: "new", createdAt: now });
    if (result.classification === "qualified") await ctx.db.insert("conciergeOutcomeEvents", { workspaceId: agent.workspaceId, agentSpecId: agent._id, leadId, type: "lead-qualified", evidenceClass: "modeled", valueCents: profile.modeledJobValueCents, source: "deterministic-intake.v1", createdAt: now });
    return { marker: "CONCIERGE_LEAD_SCORED" as const, leadId, ...result };
  },
});

/** Requests a digest-bound booking approval and refuses production until every adapter is active. */
export const requestBooking = mutation({
  args: { leadId: v.id("conciergeLeads"), environment, proposedStartAt: v.number() },
  handler: async (ctx, args) => {
    const lead = await ctx.db.get(args.leadId);
    if (!lead) throw new Error("E_CONCIERGE_LEAD_NOT_FOUND");
    await requireWorkspaceRole(ctx, lead.workspaceId, "operator");
    if (lead.classification !== "qualified" || lead.status !== "new") throw new Error("E_CONCIERGE_LEAD_NOT_BOOKABLE");
    if (!Number.isInteger(args.proposedStartAt) || args.proposedStartAt <= Date.now()) throw new Error("E_INVALID_PROPOSED_START");
    if (args.environment === "production") {
      const adapters = await ctx.db.query("conciergeAdapters").withIndex("by_agent_kind", (q) => q.eq("agentSpecId", lead.agentSpecId)).collect();
      if (!["calendar", "messaging", "billing", "model"].every((kind) => adapters.some((adapter) => adapter.kind === kind && adapter.status === "active"))) throw new Error("E_CONCIERGE_ADAPTERS_NOT_READY");
    }
    const slotDigest = receiptFingerprint([String(lead._id), args.environment, String(args.proposedStartAt)]);
    const approvalId = await ctx.db.insert("conciergeBookingApprovals", { workspaceId: lead.workspaceId, agentSpecId: lead.agentSpecId, leadId: lead._id, environment: args.environment, proposedStartAt: args.proposedStartAt, slotDigest, status: "pending", requestedAt: Date.now() });
    await ctx.db.patch(lead._id, { status: "awaiting-approval" });
    return { marker: "CONCIERGE_BOOKING_AWAITING_APPROVAL" as const, approvalId, slotDigest };
  },
});

/** Consumes one exact approval and confirms one sandbox or adapter-ready booking. */
export const approveBooking = mutation({
  args: { approvalId: v.id("conciergeBookingApprovals"), slotDigest: v.string(), approve: v.boolean() },
  handler: async (ctx, args) => {
    const approval = await ctx.db.get(args.approvalId);
    if (!approval) throw new Error("E_BOOKING_APPROVAL_NOT_FOUND");
    await requireWorkspaceRole(ctx, approval.workspaceId, "operator");
    if (approval.status !== "pending") throw new Error("E_BOOKING_APPROVAL_NOT_PENDING");
    if (args.slotDigest !== approval.slotDigest) throw new Error("E_BOOKING_SLOT_MISMATCH");
    const [lead, profile] = await Promise.all([ctx.db.get(approval.leadId), ctx.db.query("conciergeProfiles").withIndex("by_agent", (q) => q.eq("agentSpecId", approval.agentSpecId)).unique()]);
    if (!lead || !profile) throw new Error("E_CONCIERGE_PROFILE_REQUIRED");
    const now = Date.now();
    if (!args.approve) {
      await ctx.db.patch(approval._id, { status: "rejected", decidedAt: now });
      await ctx.db.patch(lead._id, { status: "closed" });
      return { marker: "CONCIERGE_BOOKING_REJECTED" as const, bookingId: null };
    }
    const bookingId = await ctx.db.insert("conciergeBookings", { workspaceId: approval.workspaceId, agentSpecId: approval.agentSpecId, leadId: lead._id, approvalId: approval._id, environment: approval.environment, startAt: approval.proposedStartAt, durationMinutes: profile.appointmentDurationMinutes, modeledValueCents: profile.modeledJobValueCents, status: "confirmed", createdAt: now });
    await ctx.db.patch(approval._id, { status: "approved", decidedAt: now });
    await ctx.db.patch(lead._id, { status: "booked" });
    await ctx.db.insert("conciergeOutcomeEvents", { workspaceId: approval.workspaceId, agentSpecId: approval.agentSpecId, leadId: lead._id, bookingId, type: "booking-confirmed", evidenceClass: "modeled", valueCents: profile.modeledJobValueCents, source: approval.environment === "sandbox" ? "sandbox-calendar.v1" : "validated-adapter.v1", createdAt: now });
    return { marker: approval.environment === "sandbox" ? "SANDBOX_BOOKING_CONFIRMED" as const : "PRODUCTION_BOOKING_CONFIRMED" as const, bookingId, evidenceClass: "modeled" as const };
  },
});

/** Appends observed business outcomes without rewriting modeled history. */
export const recordOutcome = mutation({
  args: { bookingId: v.id("conciergeBookings"), type: outcomeType, valueCents: v.optional(v.number()) },
  handler: async (ctx, args) => {
    const booking = await ctx.db.get(args.bookingId);
    if (!booking) throw new Error("E_CONCIERGE_BOOKING_NOT_FOUND");
    await requireWorkspaceRole(ctx, booking.workspaceId, "operator");
    if (args.type === "revenue-confirmed") assertIntegerRange(args.valueCents ?? -1, "revenue_value_cents", 0, 100000000);
    else if (args.valueCents !== undefined) throw new Error("E_OUTCOME_VALUE_FORBIDDEN");
    const lead = await ctx.db.get(booking.leadId);
    if (!lead) throw new Error("E_CONCIERGE_LEAD_NOT_FOUND");
    const now = Date.now();
    const outcomeId = await ctx.db.insert("conciergeOutcomeEvents", { workspaceId: booking.workspaceId, agentSpecId: booking.agentSpecId, leadId: booking.leadId, bookingId: booking._id, type: args.type, evidenceClass: "observed", valueCents: args.valueCents, source: "operator-observation.v1", createdAt: now });
    if (args.type !== "revenue-confirmed") await ctx.db.patch(booking._id, { status: args.type });
    if (["attended", "no-show", "canceled"].includes(args.type)) await ctx.db.patch(lead._id, { status: "closed" });
    return { marker: "CONCIERGE_OUTCOME_RECORDED" as const, outcomeId, evidenceClass: "observed" as const };
  },
});

/** Returns the sanitized setup, work queue, and modeled-versus-observed value dashboard. */
export const overview = query({
  args: { agentSpecId: v.id("agentSpecs") },
  handler: async (ctx, args) => {
    const agent = await agentFor(ctx, args.agentSpecId);
    await requireWorkspaceRole(ctx, agent.workspaceId, "viewer");
    const [profile, adapters, leads, approvals, bookings, outcomes] = await Promise.all([
      ctx.db.query("conciergeProfiles").withIndex("by_agent", (q) => q.eq("agentSpecId", agent._id)).unique(),
      ctx.db.query("conciergeAdapters").withIndex("by_agent_kind", (q) => q.eq("agentSpecId", agent._id)).collect(),
      ctx.db.query("conciergeLeads").withIndex("by_agent_created", (q) => q.eq("agentSpecId", agent._id)).order("desc").take(100),
      ctx.db.query("conciergeBookingApprovals").collect(),
      ctx.db.query("conciergeBookings").withIndex("by_agent_created", (q) => q.eq("agentSpecId", agent._id)).order("desc").take(100),
      ctx.db.query("conciergeOutcomeEvents").withIndex("by_agent_created", (q) => q.eq("agentSpecId", agent._id)).order("desc").take(200),
    ]);
    const scopedApprovals = approvals.filter((item) => item.agentSpecId === agent._id);
    return { marker: "CONCIERGE_OVERVIEW_READY" as const, profile, adapters: adapters.map(({ secretRef: _secretRef, ...item }) => item), leads, approvals: scopedApprovals, bookings, outcomes, metrics: { leads: leads.length, qualified: leads.filter((item) => item.classification === "qualified").length, bookings: bookings.length, attended: bookings.filter((item) => item.status === "attended").length, noShows: bookings.filter((item) => item.status === "no-show").length, canceled: bookings.filter((item) => item.status === "canceled").length, modeledPipelineValueCents: outcomes.filter((item) => item.evidenceClass === "modeled" && item.type === "booking-confirmed").reduce((sum, item) => sum + (item.valueCents ?? 0), 0), observedRevenueCents: outcomes.filter((item) => item.evidenceClass === "observed" && item.type === "revenue-confirmed").reduce((sum, item) => sum + (item.valueCents ?? 0), 0) } };
  },
});
