export type TemplateAutomation = {
  name: string;
  when: string;
  steps: readonly string[];
  approval: string;
  result: string;
  stopIf: readonly string[];
};

export type TemplateAutomationPack = {
  templateId: string;
  setupQuestions: readonly string[];
  automations: readonly TemplateAutomation[];
};

export const templateAutomationPacks: readonly TemplateAutomationPack[] = [
  {
    templateId: "trade-compliance-command",
    setupQuestions: ["What do you sell or ship?", "Which countries and routes do you use?", "Who makes the final compliance decision?", "Where are counterparties, products, orders, and licenses stored?"],
    automations: [
      { name: "Check a new trading party", when: "A customer, supplier, owner, consignee, or intermediary is created or changed", steps: ["Resolve names, aliases, addresses, and ownership", "Screen applicable official sources", "Separate false positives from reviewable matches", "Prepare the transaction-specific decision packet"], approval: "Trade compliance officer", result: "Clear, hold, or investigate—with exact reasons and a re-screen date", stopIf: ["Identity cannot be resolved", "An official source is stale or unavailable", "Product, destination, end user, or end use is missing"] },
      { name: "Recheck before shipment", when: "An order becomes ready to ship or a material shipment fact changes", steps: ["Compare against the last approved facts", "Re-screen changed parties and rules", "Check license conditions and expiry", "Bind the decision to the exact shipment"], approval: "Trade compliance officer", result: "Shipment release recommendation with a time-limited receipt", stopIf: ["Facts differ from the approved record", "A restriction or possible match appears", "The approval has expired"] },
    ],
  },
  {
    templateId: "environmental-obligation-monitor",
    setupQuestions: ["Which facilities and coordinates should be watched?", "Which air, water, waste, chemical, or land programs apply?", "Who owns each permit and report?", "Where are monitoring results and permit documents stored?"],
    automations: [
      { name: "Build the obligation calendar", when: "A facility or permit is added, amended, or renewed", steps: ["Resolve the facility across regulatory systems", "Extract requirements, thresholds, and deadlines", "Link each obligation to evidence and an owner", "Flag conflicts and missing source pages"], approval: "Environmental compliance lead", result: "Current obligation register and accountable calendar", stopIf: ["Facility identity is ambiguous", "Permit text and regulator record conflict", "An effective date cannot be proven"] },
      { name: "Respond to a monitoring exception", when: "A result exceeds a configured limit or required evidence is late", steps: ["Verify units, method, sample, and applicable limit", "Find related permit and reporting language", "Assemble trend and prior-event context", "Open the approved response playbook"], approval: "Environmental compliance lead", result: "Triage packet, deadlines, owners, and preserved evidence", stopIf: ["Units or sample identity are unresolved", "The governing limit is uncertain", "Emergency procedure applies"] },
    ],
  },
  {
    templateId: "provider-credentialing-sentinel",
    setupQuestions: ["Which professions and jurisdictions do you credential?", "What must be verified before work begins?", "Who can approve or suspend a provider?", "Where are applications, privileges, insurance, and training records stored?"],
    automations: [
      { name: "Prepare a credentialing file", when: "A provider applies or changes role, location, or specialty", steps: ["Resolve the person across submitted and primary sources", "Verify required enrollment, licenses, exclusions, and credentials", "Explain discrepancies and missing items", "Assemble the committee-ready file"], approval: "Credentialing specialist or committee", result: "Approve, pend, or decline recommendation with source receipts", stopIf: ["Identity collision exists", "A required primary source is unavailable", "An adverse action needs investigation"] },
      { name: "Continuous credential watch", when: "A license, exclusion, sanction, insurance, or certification source changes", steps: ["Match the change to the provider", "Assess affected roles and locations", "Apply the organization escalation policy", "Notify the named owner without changing privileges"], approval: "Credentialing specialist", result: "Verified alert and bounded remediation case", stopIf: ["Match confidence is insufficient", "Source status conflicts", "Immediate patient-safety escalation applies"] },
    ],
  },
  {
    templateId: "drug-safety-signal-desk",
    setupQuestions: ["Which products, ingredients, devices, and countries are in scope?", "Which safety sources and internal case systems are approved?", "What are your review and reporting clocks?", "Who performs medical and regulatory assessment?"],
    automations: [
      { name: "Triage a new safety signal", when: "A new case, regulator communication, label change, recall, or monitored pattern arrives", steps: ["Normalize product and event terms", "Deduplicate and preserve source limitations", "Retrieve label, approval, recall, and historical context", "Prepare—not decide—the signal assessment"], approval: "Qualified pharmacovigilance reviewer", result: "Traceable assessment packet and regulatory-clock status", stopIf: ["Product mapping is ambiguous", "Patient-level action is requested", "Required case data or source version is missing"] },
      { name: "Assess a label or recall change", when: "An approved label, safety notice, shortage, or recall is updated", steps: ["Diff the authoritative versions", "Identify affected products and markets", "Map internal procedures, inventory, and communications", "Create owner-specific impact tasks"], approval: "Regulatory or safety lead", result: "Approved change-impact plan with citations", stopIf: ["Market authorization cannot be resolved", "The notice is preliminary or unofficial", "A medical conclusion is required"] },
    ],
  },
  {
    templateId: "food-recall-response-desk",
    setupQuestions: ["Which products, ingredients, lots, and sites are in scope?", "Where are supplier, production, inventory, and shipment records?", "Who controls recall scope and public notices?", "Which regulator and customer channels must be monitored?"],
    automations: [
      { name: "Match a recall to your inventory", when: "A regulator, supplier, laboratory, or internal quality signal changes", steps: ["Normalize product, lot, date, establishment, and hazard", "Trace supplier-to-site-to-customer lineage", "Separate confirmed, possible, and excluded inventory", "Prepare containment and notification actions"], approval: "Food safety or quality lead", result: "Approved affected-scope ledger and response checklist", stopIf: ["Lot genealogy is incomplete", "Product identity is only a fuzzy match", "Recall scope or revision is uncertain"] },
      { name: "Prove recall completion", when: "Containment and notifications are underway", steps: ["Reconcile inventory disposition", "Track site and customer acknowledgements", "Identify unreachable or unaccounted units", "Assemble effectiveness-check evidence"], approval: "Recall coordinator", result: "Closure recommendation with unresolved exceptions", stopIf: ["Affected inventory remains unaccounted for", "A new recall revision expands scope", "Required regulator confirmation is absent"] },
    ],
  },
  {
    templateId: "uas-mission-compliance",
    setupQuestions: ["Where, when, how high, and why will you fly?", "Which pilot and aircraft will be used?", "What authorizations and operating category apply?", "Who is the remote pilot in command?"],
    automations: [
      { name: "Prepare a mission", when: "A proposed flight area and time are saved", steps: ["Resolve airspace, facility, site, and local constraints", "Check pilot, aircraft, maintenance, and authorization evidence", "Retrieve restrictions and forecast weather", "Build the mission brief and exception list"], approval: "Remote pilot in command", result: "Go/no-go preparation packet—not flight authorization", stopIf: ["Mission geometry or time is incomplete", "Authorization is missing", "Pilot or aircraft evidence is invalid"] },
      { name: "Final launch recheck", when: "The configured preflight window begins", steps: ["Refresh NOTAMs, TFRs, airspace, and weather", "Diff conditions from the approved brief", "Verify site controls and crew acknowledgement", "Present the final decision to the pilot"], approval: "Remote pilot in command", result: "Time-bound launch decision and archived evidence", stopIf: ["A dynamic source cannot refresh", "Conditions exceed policy", "Mission facts changed"] },
    ],
  },
  {
    templateId: "energy-interconnection-navigator",
    setupQuestions: ["Where is the site and which utility serves it?", "What technology and capacity are proposed?", "Which commercial deadline matters?", "Who owns engineering, land, permitting, incentives, and interconnection?"],
    automations: [
      { name: "Build a site pathway", when: "A new site or system concept is added", steps: ["Resolve parcel, utility, jurisdiction, and grid context", "Collect current tariff, queue, capacity, incentive, and permit inputs", "Map dependencies and uncertainty", "Create owner-specific diligence tasks"], approval: "Project development lead", result: "Living development path with evidence and confidence labels", stopIf: ["Utility territory or site identity conflicts", "Tariff version is uncertain", "Engineering assumptions are absent"] },
      { name: "Watch project viability", when: "A queue, tariff, incentive, permit, parcel, or cost assumption changes", steps: ["Diff the source and affected assumptions", "Recalculate only dependent scenarios", "Explain schedule, cost, and eligibility impact", "Request re-approval of invalidated decisions"], approval: "Project development lead", result: "Change brief and revised next-action recommendation", stopIf: ["A source change cannot be verified", "A professional study is superseded", "The commercial case crosses its stop threshold"] },
    ],
  },
  {
    templateId: "chemical-workplace-compliance",
    setupQuestions: ["Which sites, tasks, and worker roles are in scope?", "Where are your chemical inventory and current SDS files?", "Who owns EHS decisions and emergencies?", "Which training, controls, exposure, waste, and incident systems should connect?"],
    automations: [
      { name: "Approve a new chemical or task", when: "A substance, mixture, supplier, use, quantity, or location is proposed", steps: ["Resolve identifiers, composition, SDS revision, and intended task", "Map applicable labels, limits, controls, training, and storage rules", "Find incompatible or missing information", "Prepare the management-of-change packet"], approval: "Qualified EHS professional", result: "Approve, restrict, substitute, or reject recommendation", stopIf: ["Composition or identity is unresolved", "SDS is obsolete or unavailable", "Exposure or engineering assessment is required"] },
      { name: "Monitor site readiness", when: "Inventory, SDS, rule, training, incident, or control evidence changes", steps: ["Recompute affected obligations only", "Identify expired training, labels, inspections, or controls", "Prioritize by hazard and deadline", "Open accountable remediation tasks"], approval: "EHS professional", result: "Current site exception register and evidence status", stopIf: ["An emergency condition is detected", "Required evidence is missing", "Jurisdiction cannot be established"] },
    ],
  },
] as const;

export function automationPackFor(templateId: string): TemplateAutomationPack | undefined {
  return templateAutomationPacks.find((pack) => pack.templateId === templateId);
}
