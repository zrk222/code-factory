export const DEMO_WORKSPACE_SLUG = "factory-lab";

export type AgentSpecSemantic = {
  name: string;
  repository: string;
  providerProfile: "economy" | "balanced" | "highest-quality";
  memoryMode: "run-only" | "architecture-history";
  authorityMode: "read-only" | "propose" | "approval-required";
  hardBudgetCents: number;
  validators: string[];
};

export type MemoryExportRecord = {
  recordNumber: number;
  state: "active" | "superseded" | "erased";
  subject: string;
  content: string;
  source: string;
  purpose: string;
  provenance: string;
  confidence: number;
  retentionDays: number;
  policyVersion: "memory-policy.v1";
  createdAt: number;
  supersedesRecordNumber: number | null;
};

export type MemoryExportSource = Omit<MemoryExportRecord, "recordNumber" | "state" | "policyVersion" | "supersedesRecordNumber"> & {
  key: string;
  supersedesKey?: string;
  deletedAt?: number;
  supersededAt?: number;
};

const semanticKeys = [
  "name", "repository", "providerProfile", "memoryMode", "authorityMode", "hardBudgetCents", "validators",
] as const;

export function canonicalAgentSpec(value: AgentSpecSemantic): string {
  return JSON.stringify({
    name: value.name,
    repository: value.repository,
    providerProfile: value.providerProfile,
    memoryMode: value.memoryMode,
    authorityMode: value.authorityMode,
    hardBudgetCents: value.hardBudgetCents,
    validators: value.validators,
  });
}

export function canonicalMemoryExport(records: MemoryExportRecord[]): string {
  return JSON.stringify({
    schema: "code-factory.MemoryExport.v1",
    records: [...records].sort((left, right) => left.recordNumber - right.recordNumber),
  });
}

export function toMemoryExportRecords(sources: MemoryExportSource[]): MemoryExportRecord[] {
  const ordered = [...sources].sort((left, right) => left.createdAt - right.createdAt || left.key.localeCompare(right.key));
  const positions = new Map(ordered.map((record, index) => [record.key, index + 1]));
  return ordered.map((record, index) => {
    const erased = record.deletedAt !== undefined;
    return {
      recordNumber: index + 1,
      state: memoryExportState(record),
      subject: erasedText(erased, record.subject, "[erased]"),
      content: erasedText(erased, record.content, ""),
      source: erasedText(erased, record.source, "[erased]"),
      purpose: erasedText(erased, record.purpose, "[erased]"),
      provenance: erasedText(erased, record.provenance, "[erased]"),
      confidence: erasedNumber(erased, record.confidence),
      retentionDays: record.retentionDays,
      policyVersion: "memory-policy.v1",
      createdAt: record.createdAt,
      supersedesRecordNumber: supersedesPosition(record.supersedesKey, positions),
    };
  });
}

const memoryExportState = (record: MemoryExportSource): MemoryExportRecord["state"] => {
  if (record.deletedAt !== undefined) return "erased";
  if (record.supersededAt !== undefined) return "superseded";
  return "active";
};

const erasedText = (erased: boolean, value: string, tombstone: string): string => erased ? tombstone : value;
const erasedNumber = (erased: boolean, value: number): number => erased ? 0 : value;
const supersedesPosition = (key: string | undefined, positions: Map<string, number>): number | null => key ? positions.get(key) ?? null : null;

export function parseAgentSpecImport(payload: string): AgentSpecSemantic {
  const record = parseImportRecord(payload);
  return {
    name: importText(record, "name", 200),
    repository: importText(record, "repository", 200),
    providerProfile: importUnion(record, "providerProfile", ["economy", "balanced", "highest-quality"]),
    memoryMode: importUnion(record, "memoryMode", ["run-only", "architecture-history"]),
    authorityMode: importUnion(record, "authorityMode", ["read-only", "propose", "approval-required"]),
    hardBudgetCents: importBudget(record),
    validators: importValidators(record),
  };
}

const invalidImport = (): never => { throw new Error("E_INVALID_IMPORT"); };

const parseImportRecord = (payload: string): Record<string, unknown> => {
  if (payload.length === 0 || payload.length > 5000) return invalidImport();
  let parsed: unknown;
  try { parsed = JSON.parse(payload); } catch { return invalidImport(); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return invalidImport();
  const record = parsed as Record<string, unknown>;
  const expected = [...semanticKeys].sort();
  const keys = Object.keys(record).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]) ? record : invalidImport();
};

const importText = (record: Record<string, unknown>, key: string, maxLength: number): string =>
  typeof record[key] === "string" ? assertText(record[key], key, maxLength) : invalidImport();

const importUnion = <T extends string>(record: Record<string, unknown>, key: string, allowed: readonly T[]): T =>
  typeof record[key] === "string" && allowed.includes(record[key] as T) ? record[key] as T : invalidImport();

const importBudget = (record: Record<string, unknown>): number => {
  if (typeof record.hardBudgetCents !== "number") return invalidImport();
  assertBudget(record.hardBudgetCents, 0);
  return record.hardBudgetCents;
};

const importValidators = (record: Record<string, unknown>): string[] => {
  if (!Array.isArray(record.validators) || record.validators.length < 1 || record.validators.length > 8) return invalidImport();
  return record.validators.map((item) => typeof item === "string" ? assertText(item, "validator", 120) : invalidImport());
};

export function validateSecretReference(value: string): string {
  const normalized = assertText(value, "secret_ref", 240);
  if (/^(sk[-_]|sk-ant-|rk_(?:live|test)_|pk_(?:live|test)_|whsec_|hf_|ghp_|github_pat_|xox[baprs]-)/i.test(normalized)) {
    throw new Error("E_RAW_SECRET_FORBIDDEN");
  }
  if (!/^(env|vault|azure-key-vault|aws-secrets-manager):[A-Za-z0-9_./:-]+$/.test(normalized)) {
    throw new Error("E_INVALID_SECRET_REF");
  }
  return normalized;
}

export function assertBudget(hardBudgetCents: number, estimatedCostCents: number): void {
  if (!Number.isInteger(hardBudgetCents) || hardBudgetCents < 1) {
    throw new Error("E_INVALID_BUDGET");
  }
  if (!Number.isInteger(estimatedCostCents) || estimatedCostCents < 0) {
    throw new Error("E_INVALID_ESTIMATE");
  }
  if (estimatedCostCents > hardBudgetCents) {
    throw new Error("E_BUDGET_EXCEEDED");
  }
}

export function assertText(value: string, name: string, maxLength: number): string {
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maxLength) {
    throw new Error(`E_INVALID_${name.toUpperCase()}`);
  }
  return normalized;
}

export function assertIntegerRange(value: number, name: string, min: number, max: number): void {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`E_INVALID_${name.toUpperCase()}`);
  }
}

const PERSISTENT_INSTRUCTION_PATTERNS = [
  "ignore previous instructions",
  "reveal secrets",
  "system prompt",
  "override policy",
  "exfiltrate",
] as const;

/** Classifies persistent memory with a bounded, deterministic risk heuristic. */
export function classifyMemoryContent(content: string): {
  safetyState: "eligible" | "quarantined";
  safetyReason: "no-persistent-instruction-pattern" | "persistent-instruction-pattern";
} {
  const normalized = content.toLocaleLowerCase("en-US");
  const quarantined = PERSISTENT_INSTRUCTION_PATTERNS.some((pattern) => normalized.includes(pattern));
  return quarantined
    ? { safetyState: "quarantined", safetyReason: "persistent-instruction-pattern" }
    : { safetyState: "eligible", safetyReason: "no-persistent-instruction-pattern" };
}

export function receiptFingerprint(parts: readonly string[]): string {
  const input = parts.join("\u241f");
  let left = 0x811c9dc5;
  let right = 0x9e3779b9;
  for (let index = 0; index < input.length; index += 1) {
    const code = input.charCodeAt(index);
    left = Math.imul(left ^ code, 0x01000193) >>> 0;
    right = Math.imul(right ^ (code + index), 0x85ebca6b) >>> 0;
  }
  return left.toString(16).padStart(8, "0") + right.toString(16).padStart(8, "0");
}

export function actionDigest(repository: string, branch: string, commitSha: string): string {
  return receiptFingerprint(["propose-merge", repository, branch, commitSha]);
}

export function evidenceClass(kind: "deterministic" | "model"): "proof-bearing" | "heuristic" {
  return kind === "deterministic" ? "proof-bearing" : "heuristic";
}
