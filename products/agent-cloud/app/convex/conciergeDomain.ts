export type LeadScoreInput = {
  serviceMatch: boolean;
  areaMatch: boolean;
  urgency: "flexible" | "soon" | "urgent";
  contactReady: boolean;
  minimumLeadScore: number;
};

export type LeadScoreResult = {
  score: number;
  classification: "qualified" | "needs-review" | "rejected";
  reasons: string[];
};

/** Scores only bounded facts supplied at intake; memory and model output cannot alter qualification. */
function scoreUnmatchedLead(input: LeadScoreInput, reasons: string[]): number {
  const score = (input.serviceMatch ? 20 : 0) + (input.areaMatch ? 15 : 0) + (input.urgency === "urgent" ? 5 : 0) + (input.contactReady ? 5 : 0);
  if (!input.serviceMatch) reasons.push("service-not-matched");
  if (!input.areaMatch) reasons.push("outside-service-area");
  return score;
}

function scoreMatchedLead(input: LeadScoreInput, reasons: string[]): number {
  reasons.push("service-matched", "service-area-matched");
  return 70 + (input.urgency === "urgent" ? 15 : input.urgency === "soon" ? 10 : 5) + (input.contactReady ? 15 : 0);
}

function scoreLeadMatch(input: LeadScoreInput, reasons: string[]): number {
  if (!input.serviceMatch || !input.areaMatch) return scoreUnmatchedLead(input, reasons);
  return scoreMatchedLead(input, reasons);
}

function classifyLeadScore(score: number, minimumLeadScore: number): LeadScoreResult["classification"] {
  if (score >= minimumLeadScore) return "qualified";
  if (score >= Math.max(0, minimumLeadScore - 20)) return "needs-review";
  return "rejected";
}

export function scoreLead(input: LeadScoreInput): LeadScoreResult {
  const reasons: string[] = [];
  const score = scoreLeadMatch(input, reasons);
  if (input.contactReady) reasons.push("contact-ready");
  reasons.push(`urgency-${input.urgency}`);
  const classification = classifyLeadScore(score, input.minimumLeadScore);
  return { score, classification, reasons };
}
