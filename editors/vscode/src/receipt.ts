export interface ReceiptSummary {
  schema: string;
  feature: string;
  verdict: string;
  stage: string;
}

type JsonRecord = Record<string, unknown>;

function asRecord(value: unknown): JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : {};
}

function stringAt(record: JsonRecord, keys: string[]): string {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) {
      return value;
    }
  }
  return "Not recorded";
}

export function summarizeReceipt(value: unknown): ReceiptSummary {
  const receipt = asRecord(value);
  const rollup = asRecord(receipt.rollup);
  const result = asRecord(receipt.result);
  return {
    schema: stringAt(receipt, ["schema"]),
    feature: stringAt(receipt, ["feature", "feature_id", "name"]),
    verdict: stringAt({ ...receipt, ...rollup, ...result }, ["verdict", "status", "decision"]),
    stage: stringAt({ ...receipt, ...result }, ["stage", "gate", "command"]),
  };
}

export function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    '"': "&quot;",
  })[character] ?? character);
}

export function receiptHtml(value: unknown, title: string): string {
  const summary = summarizeReceipt(value);
  const fields = [
    ["Schema", summary.schema],
    ["Feature", summary.feature],
    ["Verdict", summary.verdict],
    ["Stage", summary.stage],
  ].map(([label, field]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(field)}</dd>`).join("");
  const payload = escapeHtml(JSON.stringify(value, null, 2));
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>body{font-family:var(--vscode-font-family);color:var(--vscode-editor-foreground);padding:20px;line-height:1.5}h1{font-size:1.2rem}dl{display:grid;grid-template-columns:max-content 1fr;gap:8px 18px;border:1px solid var(--vscode-editorWidget-border);padding:14px}dt{font-weight:700}dd{margin:0}pre{overflow:auto;padding:14px;background:var(--vscode-textCodeBlock-background)}</style></head><body><h1>${escapeHtml(title)}</h1><dl>${fields}</dl><h2>Receipt JSON</h2><pre>${payload}</pre></body></html>`;
}
