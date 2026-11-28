import * as path from "node:path";

export type ScanFinding = { code?: string; message?: string; severity?: string; path?: string; line?: number; column?: number; end_line?: number; end_column?: number };
export type DiagnosticSpec = { startLine: number; startColumn: number; endLine: number; endColumn: number; message: string; code: string; level: "error" | "warning" | "information" };

const LEVELS: Record<string, DiagnosticSpec["level"]> = { CRITICAL: "error", HIGH: "warning", MEDIUM: "warning" };

/** Arguments for a static scan of one saved file copied into an otherwise empty directory. */
export function singleFileScanArgs(root: string): string[] {
  return ["scan", "--root", root, "--static-only", "--json"];
}

/** Map `factory scan --json` findings for one file to editor ranges; null when the output is not a scan report.
 * The scanner reports 1-based lines and 0-based columns with an exclusive end, which is what the editor uses. */
export function scanDiagnosticSpecs(output: string, fileName: string): DiagnosticSpec[] | null {
  let report: unknown;
  try { report = JSON.parse(output); } catch { return null; }
  const findings = (report as { static_security?: { findings?: unknown } })?.static_security?.findings;
  if (!Array.isArray(findings)) return null;
  const base = path.basename(fileName);
  const specs: DiagnosticSpec[] = [];
  for (const item of findings as ScanFinding[]) {
    if (!item || typeof item.line !== "number" || item.line < 1 || path.basename(String(item.path ?? "")) !== base) continue;
    const startLine = item.line - 1, startColumn = Math.max(0, item.column ?? 0);
    const endLine = typeof item.end_line === "number" && item.end_line >= item.line ? item.end_line - 1 : startLine;
    const endColumn = typeof item.end_column === "number" ? Math.max(0, item.end_column) : startColumn + 1;
    specs.push({ startLine, startColumn, endLine, endColumn: endLine === startLine ? Math.max(endColumn, startColumn + 1) : endColumn,
      message: `${item.message ?? "FactoryLine static finding"} (single-file scan; cross-file context not applied)`,
      code: String(item.code ?? "FACTORY_FINDING"), level: LEVELS[String(item.severity ?? "").toUpperCase()] ?? "information" });
  }
  return specs.slice(0, 200);
}

/** factory scan exits 0 when clean and 2 when it reports findings; anything else, a kill or a buffer overflow is a failed scan. */
export function scanCompleted(error: { code?: unknown; killed?: boolean; signal?: unknown } | null): boolean {
  return error === null || (error.code === 2 && !error.killed && !error.signal);
}
