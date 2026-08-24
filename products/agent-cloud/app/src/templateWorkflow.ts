import type { BusinessTemplate } from "./templates";

export type WorkflowStep = {
  id: string;
  label: string;
  kind: "retrieve" | "reason" | "act" | "validate" | "notify";
  connectorProvider?: string;
  humanGate: boolean;
  flow?: "sequential" | "parallel" | "branch" | "loop";
  dependsOn?: string[];
  conditionRef?: string;
  maxIterations?: number;
};

function kindFor(label: string, index: number, count: number): WorkflowStep["kind"] {
  if (index === 0) return "retrieve";
  if (index === count - 1) return "validate";
  return /book|send|offer|publish|export|notify|open task/i.test(label) ? "act" : "reason";
}
/** Converts a catalog template into the exact bounded workflow shown and saved by the assembler. */
export function stepsForTemplate(template: BusinessTemplate): WorkflowStep[] {
  return template.loop.map((label, index) => ({
    id: `${template.id}-${index + 1}`,
    label,
    kind: kindFor(label, index, template.loop.length),
    humanGate: index === template.loop.length - 1 && template.authority === "approval-required",
    flow: "sequential",
    dependsOn: index === 0 ? [] : [`${template.id}-${index}`],
  }));
}

/** Converts one preset automation into a simulation-only, human-owned workflow. */
export function stepsForAutomation(templateId: string, automationIndex: number, labels: readonly string[]): WorkflowStep[] {
  return labels.map((label, index) => {
    const id = `${templateId}-automation-${automationIndex + 1}-${index + 1}`;
    return {
      id,
      label,
      kind: kindFor(label, index, labels.length),
      humanGate: index === labels.length - 1,
      flow: "sequential",
      dependsOn: index === 0 ? [] : [`${templateId}-automation-${automationIndex + 1}-${index}`],
    };
  });
}
