import { assertText, receiptFingerprint } from "./domain";

export type ComposerRuntimePreference = "auto" | "agent-oven-native" | "langgraph" | "mastra";
export type ComposerRuntime = Exclude<ComposerRuntimePreference, "auto">;
export type ComposerInferenceAccess = "agent-oven-api" | "byok";
export type ComposerStep = {
  id: string;
  label: string;
  kind: "retrieve" | "reason" | "act" | "validate" | "notify";
  humanGate: boolean;
  flow: "sequential" | "parallel" | "branch" | "loop";
  dependsOn: string[];
  maxIterations?: number;
};

export type CompiledAgentIntent = {
  marker: "AGENT_INTENT_COMPILED";
  title: string;
  selectedRuntime: ComposerRuntime;
  runtimeRationale: string;
  inferenceAccess: ComposerInferenceAccess;
  authorityPolicy: "propose" | "approval-required";
  memoryPolicy: "run-only" | "governed";
  steps: ComposerStep[];
  evidenceChecks: string[];
  clarificationQuestions: string[];
  readiness: "ready-for-draft" | "needs-clarification";
  intentDigest: string;
  compilerDigest: string;
};

const has = (value: string, expression: RegExp) => expression.test(value);

type IntentFacts = {
  consequential: boolean;
  needsKnowledge: boolean;
  repeated: boolean;
};

function analyzeIntent(description: string): IntentFacts {
  return {
    consequential: has(description, /\b(send|publish|pay|purchase|refund|delete|deploy|merge|modify|write|medical|legal|financial|production)\b/),
    needsKnowledge: has(description, /\b(document|file|repository|github|database|crm|email|slack|notion|calendar|api|source|record|webhook)\b/),
    repeated: has(description, /\b(retry|repeat|until|reconcile|monitor|continuously|loop)\b/),
  };
}

function clarificationQuestions(description: string, needsKnowledge: boolean): string[] {
  const questions: string[] = [];
  if (!has(description, /\b(success|done|acceptance|must|within|under|at least|no more|proof|verify|when)\b/)) questions.push("What exact observable result proves this agent finished successfully?");
  if (!needsKnowledge) questions.push("Which systems or approved knowledge sources may the agent read?");
  if (!has(description, /\b(read[- ]only|propose|approval|never|must not|may|allowed|cannot|without)\b/)) questions.push("Which actions may it take, and which actions always require a person?");
  if (!has(description, /\b(fail|error|timeout|retry|exception|unknown|escalat|edge case)\b/)) questions.push("What failures, exceptions, or unknowns must stop or escalate the run?");
  return questions;
}

function buildSteps(facts: IntentFacts, questionCount: number): ComposerStep[] {
  const steps: ComposerStep[] = [{ id: "clarify", label: "Validate intent and missing constraints", kind: "validate", humanGate: questionCount > 0, flow: "sequential", dependsOn: [] }];
  if (facts.needsKnowledge) steps.push({ id: "ground", label: "Retrieve approved evidence and context", kind: "retrieve", humanGate: false, flow: "parallel", dependsOn: ["clarify"] });
  steps.push({ id: "plan", label: "Plan bounded work and expected proof", kind: "reason", humanGate: false, flow: "sequential", dependsOn: [facts.needsKnowledge ? "ground" : "clarify"] });
  steps.push({ id: "execute", label: facts.consequential ? "Prepare the consequential action" : "Execute the bounded task", kind: "act", humanGate: facts.consequential, flow: facts.repeated ? "loop" : "sequential", dependsOn: ["plan"], ...(facts.repeated ? { maxIterations: 3 } : {}) });
  steps.push({ id: "verify", label: "Verify result against exact acceptance evidence", kind: "validate", humanGate: true, flow: "sequential", dependsOn: ["execute"] });
  steps.push({ id: "report", label: "Publish the result, limits, and receipt", kind: "notify", humanGate: false, flow: "sequential", dependsOn: ["verify"] });
  return steps;
}

function finishCompilation(input: {
  description: string;
  runtime: ComposerRuntime;
  rationale: string;
  inferenceAccess: ComposerInferenceAccess;
  facts: IntentFacts;
  questions: string[];
  steps: ComposerStep[];
}): CompiledAgentIntent {
  const evidenceChecks = [
    "The delivered artifact is bound to the compiled intent digest.",
    "Every required workflow step has a terminal status and evidence reference.",
    "Failures, unknowns, and skipped work remain explicit.",
    input.facts.consequential ? "A distinct human approval is bound to every consequential action." : "The result stays inside the declared authority boundary.",
  ];
  const title = input.description.split(/[.!?\n]/)[0].trim().slice(0, 96) || "Custom outcome agent";
  const intentDigest = receiptFingerprint([input.description]);
  const authorityPolicy = input.facts.consequential ? "approval-required" as const : "propose" as const;
  const memoryPolicy = input.facts.needsKnowledge ? "governed" as const : "run-only" as const;
  const canonical = JSON.stringify({ schema: "agent-oven.portable-composer.v1", title, runtime: input.runtime, inferenceAccess: input.inferenceAccess, authorityPolicy, memoryPolicy, steps: input.steps, evidenceChecks, clarificationQuestions: input.questions, intentDigest });
  return { marker: "AGENT_INTENT_COMPILED", title, selectedRuntime: input.runtime, runtimeRationale: input.rationale, inferenceAccess: input.inferenceAccess, authorityPolicy, memoryPolicy, steps: input.steps, evidenceChecks, clarificationQuestions: input.questions, readiness: input.questions.length === 0 ? "ready-for-draft" : "needs-clarification", intentDigest, compilerDigest: receiptFingerprint([canonical]) };
}

function selectRuntime(description: string, preference: ComposerRuntimePreference): { runtime: ComposerRuntime; rationale: string } {
  if (preference !== "auto") {
    const rationale = preference === "langgraph"
      ? "Selected for explicit graph state, checkpoints, interrupts, and replayable long-running work."
      : preference === "mastra"
        ? "Selected for TypeScript-native agents, tools, workflows, workspaces, and MCP composition."
        : "Selected for the smallest hosted path through Agent Oven's governed runtime.";
    return { runtime: preference, rationale };
  }
  if (has(description, /\b(checkpoints?|resume|long[- ]running|stateful|parallel|branch|interrupts?|human[- ]in[- ]the[- ]loop)\b/)) {
    return { runtime: "langgraph", rationale: "Auto-selected because the brief calls for stateful control flow, durable pause/resume, or explicit branching." };
  }
  if (has(description, /\b(typescript|mcp|slack|notion|workspace|sandbox|tool|integration|webhook)\b/)) {
    return { runtime: "mastra", rationale: "Auto-selected because the brief emphasizes TypeScript tools, integrations, workspaces, or MCP interoperability." };
  }
  return { runtime: "agent-oven-native", rationale: "Auto-selected because the brief fits a compact governed workflow without an external runtime dependency." };
}

/** Compiles a brief into reproducible governance controls without invoking a model. */
export function compileAgentIntent(input: {
  description: string;
  runtimePreference: ComposerRuntimePreference;
  inferenceAccess: ComposerInferenceAccess;
}): CompiledAgentIntent {
  const description = assertText(input.description, "agent_intent", 2400);
  if (description.length < 40) throw new Error("E_AGENT_INTENT_TOO_SHORT");
  const lower = description.toLowerCase();
  const { runtime, rationale } = selectRuntime(lower, input.runtimePreference);
  const facts = analyzeIntent(lower);
  const questions = clarificationQuestions(lower, facts.needsKnowledge);
  const steps = buildSteps(facts, questions.length);
  return finishCompilation({ description, runtime, rationale, inferenceAccess: input.inferenceAccess, facts, questions, steps });
}

export const runtimeCompatibility = [
  { runtime: "agent-oven-native", bestFor: "Fast governed hosted workflows", control: "Native jobs, budgets, approvals, receipts", activation: "Available when the hosted worker is configured" },
  { runtime: "langgraph", bestFor: "Stateful graphs, checkpoints, interrupts, replay", control: "Adapter dispatch plus Agent Oven policy and proof", activation: "Requires a validated LangGraph adapter" },
  { runtime: "mastra", bestFor: "TypeScript tools, workflows, workspaces, MCP", control: "Mastra-native dispatch plus Agent Oven policy and proof", activation: "Requires a validated Mastra adapter" },
] as const;
