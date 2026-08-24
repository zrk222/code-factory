export type RegulatedOpportunity = {
  id: string;
  templateId: string;
  label: string;
  buyer: string;
  updateCadence: "event-driven" | "daily" | "weekly";
  regulatoryUrgency: number;
  sourceFragmentation: number;
  workflowRepeatability: number;
  evidenceFit: number;
  integrationReadiness: number;
  sourceClasses: readonly string[];
  accountableOwner: string;
};

export const regulatedOpportunities: readonly RegulatedOpportunity[] = [
  { id: "trade-controls", templateId: "trade-compliance-command", label: "Trade controls and sanctions", buyer: "Exporters, importers, manufacturers, and logistics teams", updateCadence: "daily", regulatoryUrgency: 5, sourceFragmentation: 5, workflowRepeatability: 5, evidenceFit: 5, integrationReadiness: 4, sourceClasses: ["restricted-party lists", "tariff and classification sources", "license and end-use rules", "shipment and counterparty records"], accountableOwner: "trade compliance officer" },
  { id: "environmental-obligations", templateId: "environmental-obligation-monitor", label: "Environmental permits and obligations", buyer: "Industrial operators, utilities, lenders, and environmental consultants", updateCadence: "event-driven", regulatoryUrgency: 5, sourceFragmentation: 5, workflowRepeatability: 4, evidenceFit: 5, integrationReadiness: 4, sourceClasses: ["facility permits", "monitoring and discharge data", "enforcement records", "federal, state, provincial, and municipal rules"], accountableOwner: "environmental compliance lead" },
  { id: "provider-credentialing", templateId: "provider-credentialing-sentinel", label: "Healthcare provider credentialing", buyer: "Health systems, payers, staffing firms, and virtual-care networks", updateCadence: "daily", regulatoryUrgency: 5, sourceFragmentation: 5, workflowRepeatability: 5, evidenceFit: 5, integrationReadiness: 3, sourceClasses: ["identity and enrollment", "licenses", "exclusions and sanctions", "privileges, insurance, and certifications"], accountableOwner: "credentialing specialist" },
  { id: "drug-safety", templateId: "drug-safety-signal-desk", label: "Drug and device safety intelligence", buyer: "Life-science safety, quality, and regulatory teams", updateCadence: "event-driven", regulatoryUrgency: 5, sourceFragmentation: 4, workflowRepeatability: 4, evidenceFit: 5, integrationReadiness: 4, sourceClasses: ["adverse events", "labels", "recalls and shortages", "approvals and safety communications"], accountableOwner: "pharmacovigilance or regulatory lead" },
  { id: "food-response", templateId: "food-recall-response-desk", label: "Food recall and supplier response", buyer: "Manufacturers, distributors, retailers, restaurants, and institutional food services", updateCadence: "event-driven", regulatoryUrgency: 5, sourceFragmentation: 4, workflowRepeatability: 5, evidenceFit: 5, integrationReadiness: 4, sourceClasses: ["regulatory recalls", "lot and supplier records", "inventory and distribution", "customer and site notifications"], accountableOwner: "food safety or quality lead" },
  { id: "uas-operations", templateId: "uas-mission-compliance", label: "Drone mission compliance", buyer: "Survey, inspection, construction, media, emergency, and agricultural operators", updateCadence: "event-driven", regulatoryUrgency: 5, sourceFragmentation: 4, workflowRepeatability: 5, evidenceFit: 5, integrationReadiness: 4, sourceClasses: ["airspace and facility maps", "NOTAMs and temporary restrictions", "weather", "pilot, aircraft, authorization, and local-site records"], accountableOwner: "remote pilot in command" },
  { id: "energy-interconnection", templateId: "energy-interconnection-navigator", label: "Energy interconnection and permitting", buyer: "Distributed-energy developers, utilities, site owners, and project financiers", updateCadence: "weekly", regulatoryUrgency: 4, sourceFragmentation: 5, workflowRepeatability: 4, evidenceFit: 5, integrationReadiness: 3, sourceClasses: ["utility tariffs and procedures", "interconnection queues", "grid hosting capacity", "land, environmental, incentive, and permit records"], accountableOwner: "project development or interconnection lead" },
  { id: "chemical-safety", templateId: "chemical-workplace-compliance", label: "Chemical and workplace compliance", buyer: "Manufacturers, laboratories, construction firms, and safety teams", updateCadence: "event-driven", regulatoryUrgency: 5, sourceFragmentation: 4, workflowRepeatability: 5, evidenceFit: 5, integrationReadiness: 3, sourceClasses: ["chemical inventories and SDS", "workplace limits and classifications", "federal and provincial/state rules", "training, incident, and control records"], accountableOwner: "EHS professional" },
] as const;

export function opportunityScore(opportunity: RegulatedOpportunity): number {
  return opportunity.regulatoryUrgency * 3
    + opportunity.sourceFragmentation * 2
    + opportunity.workflowRepeatability * 2
    + opportunity.evidenceFit * 3
    + opportunity.integrationReadiness;
}

export function rankedRegulatedOpportunities(): readonly RegulatedOpportunity[] {
  return [...regulatedOpportunities].sort((left, right) => {
    const scoreDelta = opportunityScore(right) - opportunityScore(left);
    return scoreDelta || left.id.localeCompare(right.id);
  });
}
