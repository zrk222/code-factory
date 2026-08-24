import { v } from "convex/values";
import type { Id } from "./_generated/dataModel";
import type { MutationCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import { requireWorkspaceRole } from "./access";
import {
  assertOutcomeTransition,
  buildOutcomeContract,
  offerById,
  outcomeAgentCatalog,
  outcomePaymentRails,
  verifyOutcomeEvidence,
  type OutcomeContractState,
  type OutcomeEvidenceInput,
} from "./agentExchangeDomain";
import { assertText, receiptFingerprint } from "./domain";

const evidenceItem = v.object({
  checkId: v.string(),
  artifactRef: v.string(),
  artifactDigest: v.string(),
  status: v.union(v.literal("passed"), v.literal("failed")),
});

async function appendOutcomeEvidence(ctx: MutationCtx, workspaceId: Id<"workspaces">, contractId: Id<"outcomeContracts">, event: string, actor: string, detail: string, now: number) {
  const previous = await ctx.db.query("receipts").withIndex("by_workspace_created", (q) => q.eq("workspaceId", workspaceId)).order("desc").first();
  const fingerprint = receiptFingerprint([String(contractId), event, actor, String(now), previous?.fingerprint ?? "genesis"]);
  await ctx.db.insert("receipts", {
    workspaceId,
    outcomeContractId: contractId,
    type: "outcome-exchange",
    event,
    fingerprint,
    previousFingerprint: previous?.fingerprint,
    signatureState: "unsigned",
    createdAt: now,
  });
  await ctx.db.insert("auditEvents", { workspaceId, actor, event, targetType: "outcomeContract", targetId: String(contractId), detail, createdAt: now });
  return fingerprint;
}

async function loadContract(ctx: MutationCtx, contractId: Id<"outcomeContracts">) {
  const contract = await ctx.db.get(contractId);
  if (!contract) throw new Error("E_OUTCOME_CONTRACT_NOT_FOUND");
  return contract;
}

/** Returns the server-owned result catalog and machine-client contract after workspace authorization. */
export const catalog = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    await requireWorkspaceRole(ctx, args.workspaceId, "viewer");
    return {
      marker: "OUTCOME_AGENT_CATALOG_READY" as const,
      schema: "agent-oven.outcome-agent-catalog.v1" as const,
      offers: outcomeAgentCatalog,
      paymentRails: outcomePaymentRails,
      machineContract: {
        discovery: "/.well-known/agent-card.json",
        lifecycle: ["hire", "start", "submitEvidence", "verify", "release", "cancel"],
        authentication: "OIDC bearer token with workspace role and resource audience",
        idempotencyRequired: true,
        maximumDelegationDepth: 1,
      },
    };
  },
});

/** Reads only contracts and proof artifacts belonging to one authorized workspace. */
export const overview = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    await requireWorkspaceRole(ctx, args.workspaceId, "viewer");
    const contracts = await ctx.db.query("outcomeContracts").withIndex("by_workspace_created", (q) => q.eq("workspaceId", args.workspaceId)).order("desc").take(30);
    const account = await ctx.db.query("creditAccounts").withIndex("by_workspace", (q) => q.eq("workspaceId", args.workspaceId)).unique();
    return { marker: "OUTCOME_EXCHANGE_OVERVIEW_READY" as const, contracts, account, offers: outcomeAgentCatalog, paymentRails: outcomePaymentRails };
  },
});

/** Atomically hires one fixed offer and reserves its exact result price. */
export const hire = mutation({
  args: {
    workspaceId: v.id("workspaces"),
    offerId: v.string(),
    callerKind: v.union(v.literal("human"), v.literal("agent")),
    callerAgentId: v.optional(v.string()),
    intentRef: v.string(),
    intentDigest: v.string(),
    mandateDigest: v.optional(v.string()),
    delegationDepth: v.number(),
    idempotencyKey: v.string(),
  },
  handler: async (ctx, args) => {
    const authorized = await requireWorkspaceRole(ctx, args.workspaceId, "operator");
    const idempotencyKey = assertText(args.idempotencyKey, "idempotency_key", 120);
    const existing = await ctx.db.query("outcomeContracts").withIndex("by_workspace_key", (q) => q.eq("workspaceId", args.workspaceId).eq("idempotencyKey", idempotencyKey)).unique();
    if (existing) return { marker: "OUTCOME_IDEMPOTENCY_REPLAY" as const, contractId: existing._id, contractDigest: existing.contractDigest, resultCredits: existing.resultCredits, state: existing.state };
    const now = Date.now();
    const sealed = buildOutcomeContract({
      workspaceId: String(args.workspaceId),
      offerId: args.offerId,
      callerKind: args.callerKind,
      callerAgentId: args.callerAgentId,
      intentRef: args.intentRef,
      intentDigest: args.intentDigest,
      mandateDigest: args.mandateDigest,
      delegationDepth: args.delegationDepth,
      idempotencyKey,
      createdAt: now,
    });
    const account = await ctx.db.query("creditAccounts").withIndex("by_workspace", (q) => q.eq("workspaceId", args.workspaceId)).unique();
    if (!account || account.status !== "active") throw new Error("E_OUTCOME_CREDIT_ACCOUNT_UNAVAILABLE");
    if (account.availableCredits < sealed.offer.resultCredits) throw new Error("E_OUTCOME_CREDITS_INSUFFICIENT");
    const availableCredits = account.availableCredits - sealed.offer.resultCredits;
    const reservedCredits = account.reservedCredits + sealed.offer.resultCredits;
    const contractId = await ctx.db.insert("outcomeContracts", {
      workspaceId: args.workspaceId,
      offerId: sealed.offer.id,
      offerVersion: sealed.offer.version,
      offerName: sealed.offer.name,
      outcome: sealed.offer.outcome,
      authority: sealed.offer.authority,
      resultCredits: sealed.offer.resultCredits,
      evidenceCheckIds: sealed.offer.evidenceChecks.map((check) => check.id),
      callerKind: args.callerKind,
      callerAgentId: args.callerAgentId?.trim() || undefined,
      callerSubject: authorized.tokenIdentifier,
      intentRef: args.intentRef.trim(),
      intentDigest: args.intentDigest.trim(),
      mandateDigest: args.mandateDigest?.trim() || undefined,
      delegationDepth: args.delegationDepth,
      idempotencyKey,
      contractDigest: sealed.contractDigest,
      state: "accepted",
      paymentRail: "platform-credits",
      paymentState: "reserved",
      createdAt: now,
      expiresAt: sealed.expiresAt,
    });
    await ctx.db.patch(account._id, { availableCredits, reservedCredits, updatedAt: now });
    await ctx.db.insert("creditTransactions", { workspaceId: args.workspaceId, outcomeContractId: contractId, kind: "reserve", credits: sealed.offer.resultCredits, availableAfter: availableCredits, reservedAfter: reservedCredits, reference: idempotencyKey, createdAt: now });
    const fingerprint = await appendOutcomeEvidence(ctx, args.workspaceId, contractId, "outcome.hired", authorized.tokenIdentifier, `Offer ${sealed.offer.id} reserved ${sealed.offer.resultCredits} platform credits; external money was not settled.`, now);
    return { marker: "OUTCOME_AGENT_HIRED" as const, contractId, contractDigest: sealed.contractDigest, resultCredits: sealed.offer.resultCredits, state: "accepted" as const, fingerprint };
  },
});

/** Starts an accepted result contract without changing its price or proof obligations. */
export const start = mutation({
  args: { contractId: v.id("outcomeContracts") },
  handler: async (ctx, args) => {
    const contract = await loadContract(ctx, args.contractId);
    const authorized = await requireWorkspaceRole(ctx, contract.workspaceId, "operator");
    if (contract.expiresAt <= Date.now()) throw new Error("E_OUTCOME_CONTRACT_EXPIRED");
    assertOutcomeTransition(contract.state as OutcomeContractState, "running");
    const now = Date.now();
    await ctx.db.patch(contract._id, { state: "running", startedAt: now });
    const fingerprint = await appendOutcomeEvidence(ctx, contract.workspaceId, contract._id, "outcome.started", authorized.tokenIdentifier, "Contract execution started inside the sealed authority and price boundary.", now);
    return { marker: "OUTCOME_WORK_STARTED" as const, contractId: contract._id, state: "running" as const, fingerprint };
  },
});

/** Stores a complete digest-bound proof set; evidence text is never treated as authority. */
export const submitEvidence = mutation({
  args: { contractId: v.id("outcomeContracts"), items: v.array(evidenceItem) },
  handler: async (ctx, args) => {
    const contract = await loadContract(ctx, args.contractId);
    const authorized = await requireWorkspaceRole(ctx, contract.workspaceId, "operator");
    assertOutcomeTransition(contract.state as OutcomeContractState, "evidence-submitted");
    const proof = verifyOutcomeEvidence(contract.evidenceCheckIds, args.items as OutcomeEvidenceInput[]);
    const now = Date.now();
    for (const item of proof.items) await ctx.db.insert("outcomeEvidenceItems", { workspaceId: contract.workspaceId, outcomeContractId: contract._id, ...item, status: "passed", submittedBy: authorized.tokenIdentifier, createdAt: now });
    await ctx.db.patch(contract._id, { state: "evidence-submitted", submitterSubject: authorized.tokenIdentifier, evidenceDigest: proof.evidenceDigest, evidenceSubmittedAt: now });
    const fingerprint = await appendOutcomeEvidence(ctx, contract.workspaceId, contract._id, "outcome.evidence-submitted", authorized.tokenIdentifier, `${proof.items.length} required proof items stored by digest; no payout released.`, now);
    return { marker: "OUTCOME_EVIDENCE_SUBMITTED" as const, contractId: contract._id, evidenceDigest: proof.evidenceDigest, state: "evidence-submitted" as const, fingerprint };
  },
});

/** Recomputes the exact evidence verdict under an identity distinct from the submitter. */
export const verify = mutation({
  args: { contractId: v.id("outcomeContracts") },
  handler: async (ctx, args) => {
    const contract = await loadContract(ctx, args.contractId);
    const authorized = await requireWorkspaceRole(ctx, contract.workspaceId, "reviewer");
    if (contract.state !== "evidence-submitted" || !contract.evidenceDigest || !contract.submitterSubject) throw new Error("E_OUTCOME_NOT_VERIFIABLE");
    if (contract.submitterSubject === authorized.tokenIdentifier) throw new Error("E_SELF_VERIFICATION_FORBIDDEN");
    const items = await ctx.db.query("outcomeEvidenceItems").withIndex("by_contract_check", (q) => q.eq("outcomeContractId", contract._id)).collect();
    const proof = verifyOutcomeEvidence(contract.evidenceCheckIds, items.map((item) => ({ checkId: item.checkId, artifactRef: item.artifactRef, artifactDigest: item.artifactDigest, status: item.status })));
    if (proof.evidenceDigest !== contract.evidenceDigest) throw new Error("E_OUTCOME_EVIDENCE_DIGEST_MISMATCH");
    assertOutcomeTransition(contract.state, "verified");
    const now = Date.now();
    const verdictDigest = receiptFingerprint([contract.contractDigest, proof.evidenceDigest, authorized.tokenIdentifier, "passed"]);
    await ctx.db.insert("outcomeVerdicts", { workspaceId: contract.workspaceId, outcomeContractId: contract._id, result: "passed", evidenceDigest: proof.evidenceDigest, verdictDigest, verifierSubject: authorized.tokenIdentifier, createdAt: now });
    await ctx.db.patch(contract._id, { state: "verified", verifierSubject: authorized.tokenIdentifier, verdictDigest, verifiedAt: now });
    const fingerprint = await appendOutcomeEvidence(ctx, contract.workspaceId, contract._id, "outcome.verified", authorized.tokenIdentifier, "Independent deterministic evidence set passed; credits remain reserved until administrator release.", now);
    return { marker: "OUTCOME_VERDICT_PASSED" as const, contractId: contract._id, verdictDigest, state: "verified" as const, payableCredits: contract.resultCredits, fingerprint };
  },
});

/** Settles the exact reserved result price after a passed independent verdict. */
export const release = mutation({
  args: { contractId: v.id("outcomeContracts") },
  handler: async (ctx, args) => {
    const contract = await loadContract(ctx, args.contractId);
    const authorized = await requireWorkspaceRole(ctx, contract.workspaceId, "admin");
    if (contract.state === "paid") return { marker: "OUTCOME_PAYMENT_REPLAY" as const, contractId: contract._id, state: contract.state, settledCredits: 0 };
    assertOutcomeTransition(contract.state as OutcomeContractState, "paid");
    if (contract.paymentState !== "reserved" || !contract.verdictDigest) throw new Error("E_OUTCOME_PAYMENT_NOT_PAYABLE");
    const account = await ctx.db.query("creditAccounts").withIndex("by_workspace", (q) => q.eq("workspaceId", contract.workspaceId)).unique();
    if (!account || account.reservedCredits < contract.resultCredits) throw new Error("E_OUTCOME_RESERVATION_MISSING");
    const now = Date.now();
    const reservedCredits = account.reservedCredits - contract.resultCredits;
    const spentCredits = account.spentCredits + contract.resultCredits;
    await ctx.db.patch(account._id, { reservedCredits, spentCredits, updatedAt: now });
    await ctx.db.patch(contract._id, { state: "paid", paymentState: "settled", paidAt: now });
    await ctx.db.insert("creditTransactions", { workspaceId: contract.workspaceId, outcomeContractId: contract._id, kind: "settle", credits: contract.resultCredits, availableAfter: account.availableCredits, reservedAfter: reservedCredits, reference: contract.contractDigest, createdAt: now });
    const fingerprint = await appendOutcomeEvidence(ctx, contract.workspaceId, contract._id, "outcome.paid", authorized.tokenIdentifier, `${contract.resultCredits} platform credits settled after the independent verdict.`, now);
    return { marker: "OUTCOME_PAYMENT_SETTLED" as const, contractId: contract._id, state: "paid" as const, settledCredits: contract.resultCredits, fingerprint };
  },
});

/** Stops an unpaid contract and releases its result-credit reservation exactly once. */
export const cancel = mutation({
  args: { contractId: v.id("outcomeContracts"), disposition: v.union(v.literal("canceled"), v.literal("disputed")), reason: v.string() },
  handler: async (ctx, args) => {
    const contract = await loadContract(ctx, args.contractId);
    const authorized = await requireWorkspaceRole(ctx, contract.workspaceId, "admin");
    if (contract.state === "canceled" || contract.state === "disputed") return { marker: "OUTCOME_TERMINATION_REPLAY" as const, contractId: contract._id, state: contract.state, releasedCredits: 0 };
    assertOutcomeTransition(contract.state as OutcomeContractState, args.disposition);
    if (contract.paymentState !== "reserved") throw new Error("E_OUTCOME_RESERVATION_NOT_RELEASABLE");
    const reason = assertText(args.reason, "termination_reason", 500);
    const account = await ctx.db.query("creditAccounts").withIndex("by_workspace", (q) => q.eq("workspaceId", contract.workspaceId)).unique();
    if (!account || account.reservedCredits < contract.resultCredits) throw new Error("E_OUTCOME_RESERVATION_MISSING");
    const now = Date.now();
    const availableCredits = account.availableCredits + contract.resultCredits;
    const reservedCredits = account.reservedCredits - contract.resultCredits;
    await ctx.db.patch(account._id, { availableCredits, reservedCredits, updatedAt: now });
    await ctx.db.patch(contract._id, { state: args.disposition, paymentState: "released", terminatedAt: now, terminationReason: reason });
    await ctx.db.insert("creditTransactions", { workspaceId: contract.workspaceId, outcomeContractId: contract._id, kind: "release", credits: contract.resultCredits, availableAfter: availableCredits, reservedAfter: reservedCredits, reference: contract.contractDigest, createdAt: now });
    const fingerprint = await appendOutcomeEvidence(ctx, contract.workspaceId, contract._id, `outcome.${args.disposition}`, authorized.tokenIdentifier, `${contract.resultCredits} reserved platform credits released; reason stored separately from payment credentials.`, now);
    return { marker: "OUTCOME_CONTRACT_TERMINATED" as const, contractId: contract._id, state: args.disposition, releasedCredits: contract.resultCredits, fingerprint };
  },
});
