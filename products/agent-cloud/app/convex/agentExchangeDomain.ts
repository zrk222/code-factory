import { receiptFingerprint } from "./domain";

export type OutcomeContractState =
  | "accepted"
  | "running"
  | "evidence-submitted"
  | "verified"
  | "paid"
  | "disputed"
  | "canceled";

export type OutcomeAgentOffer = {
  id: string;
  version: 1;
  name: string;
  category: "engineering" | "security" | "support" | "data" | "finance-ops" | "compliance";
  outcome: string;
  deliverable: string;
  authority: string;
  resultCredits: number;
  deliveryHours: number;
  evidenceChecks: readonly { id: string; label: string }[];
};

export const outcomeAgentCatalog: readonly OutcomeAgentOffer[] = [
  {
    id: "pr-evidence-auditor",
    version: 1,
    name: "PR Evidence Auditor",
    category: "engineering",
    outcome: "A review-ready pull-request proof packet with hollow checks called out.",
    deliverable: "Requirements map, changed-risk inventory, validator results, and evidence digest.",
    authority: "Read repository evidence and propose findings; cannot merge or modify code.",
    resultCredits: 90,
    deliveryHours: 4,
    evidenceChecks: [
      { id: "requirements-bound", label: "Requirements are mapped to changed behavior" },
      { id: "negative-proof", label: "At least one negative-path proof is bound" },
      { id: "artifact-digests", label: "All referenced artifacts have stable digests" },
      { id: "scope-reviewed", label: "Changed scope and exclusions are explicit" },
    ],
  },
  {
    id: "security-questionnaire-agent",
    version: 1,
    name: "Security Questionnaire Agent",
    category: "security",
    outcome: "A source-linked security questionnaire packet ready for accountable approval.",
    deliverable: "Answer draft, source references, unknowns, and approval queue.",
    authority: "Read approved security sources and draft; cannot certify or submit externally.",
    resultCredits: 120,
    deliveryHours: 8,
    evidenceChecks: [
      { id: "answers-sourced", label: "Every factual answer has an approved source" },
      { id: "unknowns-preserved", label: "Unsupported answers remain explicit unknowns" },
      { id: "claims-bounded", label: "No certification or compliance status is invented" },
      { id: "approval-ready", label: "Submission remains behind a human approval" },
    ],
  },
  {
    id: "support-resolution-agent",
    version: 1,
    name: "Support Resolution Agent",
    category: "support",
    outcome: "A policy-grounded support resolution packet for one customer case.",
    deliverable: "Case summary, proposed reply, policy citations, next action, and escalation state.",
    authority: "Read the case and approved policy; cannot issue refunds or send replies without approval.",
    resultCredits: 60,
    deliveryHours: 2,
    evidenceChecks: [
      { id: "case-bound", label: "Resolution is bound to one case reference" },
      { id: "policy-sourced", label: "Material actions cite approved policy" },
      { id: "escalation-checked", label: "Escalation conditions are evaluated" },
      { id: "send-gated", label: "External send remains approval-gated" },
    ],
  },
  {
    id: "data-quality-reconciler",
    version: 1,
    name: "Data Quality Reconciler",
    category: "data",
    outcome: "An accepted discrepancy report for one declared dataset boundary.",
    deliverable: "Input digests, anomaly list, reconciliation rules, and proposed remediation.",
    authority: "Read bounded datasets and propose fixes; cannot silently write production data.",
    resultCredits: 140,
    deliveryHours: 12,
    evidenceChecks: [
      { id: "inputs-digested", label: "Every compared input has a digest" },
      { id: "rules-declared", label: "Reconciliation rules are declared before verdict" },
      { id: "anomalies-reproducible", label: "Reported anomalies reproduce from the same inputs" },
      { id: "writes-gated", label: "Production writes remain separately authorized" },
    ],
  },
  {
    id: "invoice-exception-triage",
    version: 1,
    name: "Invoice Exception Triage",
    category: "finance-ops",
    outcome: "A categorized, evidence-linked exception packet for one invoice batch.",
    deliverable: "Exception classes, source references, recommended route, and approval list.",
    authority: "Read invoice metadata and propose routing; cannot approve invoices or move money.",
    resultCredits: 100,
    deliveryHours: 6,
    evidenceChecks: [
      { id: "batch-bound", label: "Triage is bound to one immutable batch" },
      { id: "exceptions-supported", label: "Every exception has source evidence" },
      { id: "duplicates-checked", label: "Duplicate and replay conditions are checked" },
      { id: "payment-forbidden", label: "No payment execution authority is present" },
    ],
  },
  {
    id: "compliance-evidence-monitor",
    version: 1,
    name: "Compliance Evidence Monitor",
    category: "compliance",
    outcome: "A source-linked change and evidence-gap packet for one declared control set.",
    deliverable: "Control deltas, source timestamps, evidence gaps, and accountable owner queue.",
    authority: "Observe approved sources and report gaps; cannot certify compliance.",
    resultCredits: 160,
    deliveryHours: 24,
    evidenceChecks: [
      { id: "controls-scoped", label: "The evaluated control set is explicit" },
      { id: "sources-current", label: "Source timestamps and freshness are recorded" },
      { id: "gaps-not-guessed", label: "Missing evidence remains missing rather than estimated" },
      { id: "non-certifying", label: "The packet makes no compliance certification" },
    ],
  },
] as const;

export const outcomePaymentRails = [
  { rail: "platform-credits" as const, status: "active" as const, detail: "Atomic internal result-credit reservation and settlement." },
  { rail: "stripe-connect" as const, status: "setup-required" as const, detail: "Requires connected-account onboarding, webhooks, refunds, disputes, and provider read-back." },
  { rail: "mpp" as const, status: "setup-required" as const, detail: "Requires a verified machine-payment provider and signed authorization flow." },
  { rail: "x402" as const, status: "setup-required" as const, detail: "Requires a verified facilitator or settlement implementation and replay protection." },
] as const;

export type OutcomeContractInput = {
  workspaceId: string;
  offerId: string;
  callerKind: "human" | "agent";
  callerAgentId?: string;
  intentRef: string;
  intentDigest: string;
  mandateDigest?: string;
  delegationDepth: number;
  idempotencyKey: string;
  createdAt: number;
};

export type OutcomeEvidenceInput = {
  checkId: string;
  artifactRef: string;
  artifactDigest: string;
  status: "passed" | "failed";
};

const boundedText = (value: string | undefined, name: string, maximum: number): string => {
  const normalized = value?.trim() ?? "";
  if (normalized.length === 0 || normalized.length > maximum) throw new Error(`E_INVALID_${name.toUpperCase()}`);
  return normalized;
};

export function offerById(offerId: string): OutcomeAgentOffer {
  const offer = outcomeAgentCatalog.find((candidate) => candidate.id === offerId);
  if (!offer) throw new Error("E_OUTCOME_OFFER_NOT_FOUND");
  return offer;
}

export function buildOutcomeContract(input: OutcomeContractInput) {
  const offer = offerById(input.offerId);
  if (!Number.isInteger(input.delegationDepth) || input.delegationDepth < 0 || input.delegationDepth > 1) throw new Error("E_DELEGATION_DEPTH_EXCEEDED");
  if (input.callerKind === "agent") {
    boundedText(input.callerAgentId, "caller_agent_id", 160);
    boundedText(input.mandateDigest, "mandate_digest", 120);
  }
  const workspaceId = boundedText(input.workspaceId, "workspace_id", 160);
  const intentRef = boundedText(input.intentRef, "intent_ref", 500);
  const intentDigest = boundedText(input.intentDigest, "intent_digest", 120);
  const idempotencyKey = boundedText(input.idempotencyKey, "idempotency_key", 120);
  const mandateDigest = input.mandateDigest ? boundedText(input.mandateDigest, "mandate_digest", 120) : undefined;
  if (!Number.isInteger(input.createdAt) || input.createdAt <= 0) throw new Error("E_INVALID_CREATED_AT");
  const expiresAt = input.createdAt + 24 * 60 * 60 * 1000;
  const canonical = JSON.stringify({
    schema: "agent-oven.outcome-contract.v1",
    workspaceId,
    offerId: offer.id,
    offerVersion: offer.version,
    callerKind: input.callerKind,
    callerAgentId: input.callerAgentId?.trim() || null,
    intentRef,
    intentDigest,
    mandateDigest: mandateDigest ?? null,
    delegationDepth: input.delegationDepth,
    resultCredits: offer.resultCredits,
    evidenceCheckIds: offer.evidenceChecks.map((check) => check.id),
    authority: offer.authority,
    idempotencyKey,
    createdAt: input.createdAt,
    expiresAt,
  });
  return {
    marker: "OUTCOME_CONTRACT_SEALED" as const,
    offer,
    canonical,
    contractDigest: receiptFingerprint([canonical]),
    expiresAt,
  };
}

const transitions: Record<OutcomeContractState, readonly OutcomeContractState[]> = {
  accepted: ["running", "canceled"],
  running: ["evidence-submitted", "canceled"],
  "evidence-submitted": ["verified", "disputed", "canceled"],
  verified: ["paid", "disputed", "canceled"],
  paid: [],
  disputed: [],
  canceled: [],
};

export function assertOutcomeTransition(current: OutcomeContractState, next: OutcomeContractState): void {
  if (!transitions[current].includes(next)) throw new Error("E_OUTCOME_TRANSITION_INVALID");
}

export function verifyOutcomeEvidence(requiredCheckIds: readonly string[], items: readonly OutcomeEvidenceInput[]) {
  if (items.length !== requiredCheckIds.length) throw new Error("E_OUTCOME_EVIDENCE_INCOMPLETE");
  const required = new Set(requiredCheckIds);
  const seen = new Set<string>();
  const normalized = items.map((item) => {
    const checkId = boundedText(item.checkId, "check_id", 120);
    if (!required.has(checkId)) throw new Error("E_OUTCOME_EVIDENCE_UNKNOWN_CHECK");
    if (seen.has(checkId)) throw new Error("E_OUTCOME_EVIDENCE_DUPLICATE_CHECK");
    seen.add(checkId);
    if (item.status !== "passed") throw new Error("E_OUTCOME_EVIDENCE_FAILED");
    return {
      checkId,
      artifactRef: boundedText(item.artifactRef, "artifact_ref", 500),
      artifactDigest: boundedText(item.artifactDigest, "artifact_digest", 120),
      status: item.status,
    };
  }).sort((left, right) => left.checkId.localeCompare(right.checkId));
  if (requiredCheckIds.some((checkId) => !seen.has(checkId))) throw new Error("E_OUTCOME_EVIDENCE_INCOMPLETE");
  const canonical = JSON.stringify({ schema: "agent-oven.outcome-evidence.v1", items: normalized });
  return { marker: "OUTCOME_EVIDENCE_VERIFIED" as const, canonical, evidenceDigest: receiptFingerprint([canonical]), items: normalized };
}
