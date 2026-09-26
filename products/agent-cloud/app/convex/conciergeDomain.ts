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
export function scoreLead(input: LeadScoreInput): LeadScoreResult {
  const reasons: string[] = [];
  let score: number;
  if (!input.serviceMatch || !input.areaMatch) {
    score = (input.serviceMatch ? 20 : 0) + (input.areaMatch ? 15 : 0) + (input.urgency === "urgent" ? 5 : 0) + (input.contactReady ? 5 : 0);
    if (!input.serviceMatch) reasons.push("service-not-matched");
    if (!input.areaMatch) reasons.push("outside-service-area");
  } else {
    score = 70 + (input.urgency === "urgent" ? 15 : input.urgency === "soon" ? 10 : 5) + (input.contactReady ? 15 : 0);
    reasons.push("service-matched", "service-area-matched");
  }
  if (input.contactReady) reasons.push("contact-ready");
  reasons.push(`urgency-${input.urgency}`);
  const classification = score >= input.minimumLeadScore
    ? "qualified"
    : score >= Math.max(0, input.minimumLeadScore - 20)
      ? "needs-review"
      : "rejected";
  return { score, classification, reasons };
}
