import * as childProcess from "node:child_process";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as vscode from "vscode";
import { factoryExecutable } from "./runner";
import { scanCompleted, scanDiagnosticSpecs, singleFileScanArgs } from "./scan";

const LEVEL = { error: vscode.DiagnosticSeverity.Error, warning: vscode.DiagnosticSeverity.Warning, information: vscode.DiagnosticSeverity.Information };
const SCAN_TIMEOUT_MS = 20_000;
const MAX_CONCURRENT_SCANS = 2;
const inFlight = new Set<string>();
const rescan = new Map<string, vscode.TextDocument>();
let running = 0;

function runScan(root: string): Promise<string> {
  const command = vscode.workspace.getConfiguration("factoryline").get<string>("command", "factory");
  return new Promise((resolve, reject) => {
    childProcess.execFile(factoryExecutable(command), singleFileScanArgs(root), { timeout: SCAN_TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024, windowsHide: true },
      (error, out) => (scanCompleted(error as never) ? resolve(out) : reject(error ?? new Error("FactoryLine scan failed"))));
  });
}

async function scanDocument(diagnostics: vscode.DiagnosticCollection, document: vscode.TextDocument, manual: boolean): Promise<void> {
  if (!vscode.workspace.isTrusted || document.uri.scheme !== "file" || document.languageId !== "python") {
    if (manual) void vscode.window.showWarningMessage("FactoryLine scans saved Python files in a trusted workspace.");
    return;
  }
  const key = document.uri.toString();
  if (inFlight.has(key) || running >= MAX_CONCURRENT_SCANS) { rescan.set(key, document); return; }
  inFlight.add(key);
  running += 1;
  const version = document.version;
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "factoryline-scan-"));
  try {
    await fs.writeFile(path.join(dir, path.basename(document.fileName)), document.getText(), "utf8");
    const specs = scanDiagnosticSpecs(await runScan(dir), document.fileName);
    if (specs === null) throw new Error("the scan output was not a FactoryLine report");
    if (document.isClosed || document.version !== version) return;
    diagnostics.set(document.uri, specs.map(spec => {
      const item = new vscode.Diagnostic(new vscode.Range(spec.startLine, spec.startColumn, spec.endLine, spec.endColumn), spec.message, LEVEL[spec.level]);
      item.source = "FactoryLine scan";
      item.code = spec.code;
      return item;
    }));
  } catch (error) {
    // A failed scan keeps the previous diagnostics rather than reporting the file clean.
    if (manual) void vscode.window.showErrorMessage(`FactoryLine scan failed: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    inFlight.delete(key);
    running -= 1;
    await fs.rm(dir, { recursive: true, force: true });
    const next = rescan.entries().next().value as [string, vscode.TextDocument] | undefined;
    if (next) { rescan.delete(next[0]); if (!next[1].isClosed) void scanDocument(diagnostics, next[1], false); }
  }
}

/** Opt-in scan-on-save: one saved file, static checks only, results as editor diagnostics. */
export function registerScanOnSave(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection("factoryline-scan");
  const enabled = () => vscode.workspace.getConfiguration("factoryline").get<boolean>("scanOnSave", false);
  if (enabled() && vscode.workspace.isTrusted) {
    // Pay the CLI's cold start once, before the first save.
    void fs.mkdtemp(path.join(os.tmpdir(), "factoryline-warm-")).then(dir => runScan(dir).catch(() => "").finally(() => fs.rm(dir, { recursive: true, force: true })));
  }
  context.subscriptions.push(
    diagnostics,
    vscode.workspace.onDidSaveTextDocument(document => { if (enabled()) void scanDocument(diagnostics, document, false); }),
    vscode.workspace.onDidCloseTextDocument(document => { rescan.delete(document.uri.toString()); diagnostics.delete(document.uri); }),
    vscode.commands.registerCommand("factoryline.scanCurrentFile", async () => {
      const document = vscode.window.activeTextEditor?.document;
      if (!document) return;
      if (document.isDirty) await document.save();
      await scanDocument(diagnostics, document, true);
    }),
  );
}
