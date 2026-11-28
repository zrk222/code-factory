import * as childProcess from "node:child_process";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as vscode from "vscode";
import { factoryExecutable } from "./runner";
import { scanDiagnosticSpecs, singleFileScanArgs } from "./scan";

const LEVEL = { error: vscode.DiagnosticSeverity.Error, warning: vscode.DiagnosticSeverity.Warning, information: vscode.DiagnosticSeverity.Information };
const SCAN_TIMEOUT_MS = 20_000;
const inFlight = new Set<string>();

async function scanDocument(diagnostics: vscode.DiagnosticCollection, document: vscode.TextDocument, manual: boolean): Promise<void> {
  if (!vscode.workspace.isTrusted || document.uri.scheme !== "file" || document.languageId !== "python") {
    if (manual) void vscode.window.showWarningMessage("FactoryLine scans saved Python files in a trusted workspace.");
    return;
  }
  const key = document.uri.toString();
  if (inFlight.has(key)) return;
  inFlight.add(key);
  const version = document.version;
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "factoryline-scan-"));
  try {
    await fs.writeFile(path.join(dir, path.basename(document.fileName)), document.getText(), "utf8");
    const command = vscode.workspace.getConfiguration("factoryline").get<string>("command", "factory");
    const stdout = await new Promise<string>((resolve, reject) => {
      childProcess.execFile(factoryExecutable(command), singleFileScanArgs(dir), { timeout: SCAN_TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024, windowsHide: true },
        (error, out) => (out ? resolve(out) : reject(error ?? new Error("FactoryLine scan produced no output"))));
    });
    if (document.isClosed || document.version !== version) return;
    diagnostics.set(document.uri, scanDiagnosticSpecs(stdout, document.fileName).map(spec => {
      const item = new vscode.Diagnostic(new vscode.Range(spec.startLine, spec.startColumn, spec.endLine, spec.endColumn), spec.message, LEVEL[spec.level]);
      item.source = "FactoryLine scan";
      item.code = spec.code;
      return item;
    }));
  } catch (error) {
    if (manual) void vscode.window.showErrorMessage(`FactoryLine scan failed: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    inFlight.delete(key);
    await fs.rm(dir, { recursive: true, force: true });
  }
}

/** Opt-in scan-on-save: one saved file, static checks only, results as editor diagnostics. */
export function registerScanOnSave(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection("factoryline-scan");
  context.subscriptions.push(
    diagnostics,
    vscode.workspace.onDidSaveTextDocument(document => {
      if (vscode.workspace.getConfiguration("factoryline").get<boolean>("scanOnSave", false)) void scanDocument(diagnostics, document, false);
    }),
    vscode.workspace.onDidCloseTextDocument(document => diagnostics.delete(document.uri)),
    vscode.commands.registerCommand("factoryline.scanCurrentFile", async () => {
      const document = vscode.window.activeTextEditor?.document;
      if (!document) return;
      if (document.isDirty) await document.save();
      await scanDocument(diagnostics, document, true);
    }),
  );
}
