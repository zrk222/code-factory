const fixedTemplateCredits: Record<string, number> = {
  "qualified-match-board": 40,
  "booked-job-concierge": 55,
  "personal-briefing": 30,
  "outcome-generator": 25,
  "citable-comparison-lab": 90,
  "autonomous-micro-utility": 45,
  "books-close-assistant": 120,
  "adaptive-exam-coach": 40,
  "community-memory-guide": 85,
  "certified-domain-transcript": 110,
  "career-concierge": 70,
  "calendar-yield-manager": 60,
  "legal-research-workbench": 180,
  "broker-mls-intelligence": 160,
  "homebuyer-seller-guide": 90,
  "civic-planning-intelligence": 190,
  "security-questionnaire-room": 110,
  "rfp-response-studio": 100,
  "receivables-resolution-agent": 85,
  "compliance-evidence-desk": 140,
  "trade-compliance-command": 175,
  "environmental-obligation-monitor": 160,
  "provider-credentialing-sentinel": 160,
  "drug-safety-signal-desk": 185,
  "food-recall-response-desk": 170,
  "uas-mission-compliance": 135,
  "energy-interconnection-navigator": 180,
  "chemical-workplace-compliance": 165,
};

export function quoteBlueprintCredits(input: { templateId: string; steps: readonly unknown[]; triggerKind: string; memoryPolicy: string; evidenceLevel: string }) {
  const fixed = fixedTemplateCredits[input.templateId];
  if (fixed !== undefined) return { pricingMode: "fixed-template" as const, total: fixed, lineItems: [{ label: "Published template activation", credits: fixed }] };
  const lineItems = [
    { label: "Custom blueprint base", credits: 20 },
    { label: `${input.steps.length} workflow ingredients`, credits: input.steps.length * 4 },
    { label: "Automation trigger", credits: input.triggerKind === "manual" ? 0 : 8 },
    { label: "Memory ingredient", credits: input.memoryPolicy === "governed" ? 15 : input.memoryPolicy === "run-only" ? 5 : 0 },
    { label: "Evidence ingredient", credits: input.evidenceLevel === "full" ? 10 : 0 },
  ].filter((item) => item.credits > 0);
  return { pricingMode: "base-plus-ingredients" as const, total: lineItems.reduce((sum, item) => sum + item.credits, 0), lineItems };
}
