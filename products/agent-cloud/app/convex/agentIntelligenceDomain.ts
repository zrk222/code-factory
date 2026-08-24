export type ComplianceRule = {
  ruleId: string;
  predicate: "required-before" | "forbidden-after" | "requires-human-gate" | "max-count";
  subjectStep: string;
  relatedStep?: string;
  maxCount?: number;
};

const secretPattern = /(?:bearer\s+[a-z0-9._-]+|(?:api[_-]?key|password|secret|token)\s*[:=]\s*\S+|(?:sk[-_]|sk-ant-|rk_(?:live|test)_|whsec_|hf_|ghp_|github_pat_|xox[baprs]-)[a-z0-9._-]+)/gi;
const emailPattern = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const phonePattern = /(?:\+?\d[\d(). -]{8,}\d)/g;

/** Removes sensitive values before operational metadata can be persisted. */
export function redactOperationalText(value: string): string {
  return value.replace(secretPattern, "[REDACTED_SECRET]").replace(emailPattern, "[REDACTED_EMAIL]").replace(phonePattern, "[REDACTED_PHONE]");
}

/** Evaluates published manual rules against an executed path and explicit human gates. */
export function evaluateCompliancePath(path: readonly string[], humanGates: readonly string[], rules: readonly ComplianceRule[]) {
  const violations = rules.filter((rule) => violatesRule(path, humanGates, rule)).map((rule) => rule.ruleId);
  return { passed: violations.length === 0, violations };
}

function indexesOf(path: readonly string[], stepId: string | undefined): number[] {
  return path.flatMap((step, index) => step === stepId ? [index] : []);
}

function violatesRule(path: readonly string[], humanGates: readonly string[], rule: ComplianceRule): boolean {
  const subjects = indexesOf(path, rule.subjectStep);
  const related = indexesOf(path, rule.relatedStep);
  if (rule.predicate === "required-before") return subjects.some((index) => !related.some((candidate) => candidate < index));
  if (rule.predicate === "forbidden-after") return subjects.some((index) => related.some((candidate) => candidate < index));
  if (rule.predicate === "requires-human-gate") return subjects.length > 0 && !humanGates.includes(rule.subjectStep);
  return subjects.length > (rule.maxCount ?? 0);
}
