import * as childProcess from "node:child_process";
import { type Dirent } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as vscode from "vscode";
import { receiptHtml } from "./receipt";
import { meterHtml, savingsHtml } from "./meter";
import { factoryExecutable, factoryStudioUrl, isFeatureName } from "./runner";
import { createUnapprovedRequirementProofDraft, findRequirementEvidence, MAX_TEST_DECLARATIONS_PER_DOCUMENT, MAX_TEST_PROOF_DOCUMENT_BYTES, MAX_TEST_PROOF_DOCUMENT_CHARS, readTestProofManifest, requirementIds, testDeclarations, testProofId } from "./requirement";
import { GITHUB_REPOSITORY_URL, shouldOfferGitHubStar, starPromptKey } from "./star_prompt";
import { registerEvidence } from "./evidence";
import { registerScanOnSave } from "./scan_on_save";
import { runCommand } from "@factoryline/proof-client";

const output = vscode.window.createOutputChannel("FactoryLine");
const receiptDirectories = [".factory", "receipts"];
let studioProcess: childProcess.ChildProcessWithoutNullStreams | undefined;
let studioUrl: string | undefined;

class RequirementCodeLensProvider implements vscode.CodeLensProvider {
  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const lenses: vscode.CodeLens[] = [];
    for (let line = 0; line < document.lineCount; line += 1) {
      const text = document.lineAt(line).text;
      for (const requirementId of requirementIds(text)) {
        lenses.push(new vscode.CodeLens(new vscode.Range(line, 0, line, text.length), {
          command: "factoryline.openRequirementEvidence",
          title: `FactoryLine: open proof for ${requirementId}`,
          arguments: [requirementId],
        }));
      }
    }
    for (const test of testDeclarations(document.getText(), document.languageId)) {
      lenses.push(new vscode.CodeLens(new vscode.Range(test.line, 0, test.line, document.lineAt(test.line).text.length), {
        command: "factoryline.draftTestProof",
        title: `FactoryLine: draft unapproved proof for ${test.name} (line ${test.line + 1})`,
        arguments: [document.uri, test.line, test.name],
      }));
    }
    return lenses;
  }
}

const testProofDiagnostics = vscode.languages.createDiagnosticCollection("factoryline-test-proof");
interface DiagnosticRefreshState { version: number; timer?: NodeJS.Timeout; controller?: AbortController }
const diagnosticRefreshes = new Map<string, DiagnosticRefreshState>();

function refreshTestProofDiagnostics(document: vscode.TextDocument): void {
  const key = document.uri.toString();
  const state = diagnosticRefreshes.get(key) ?? { version: 0 };
  state.version += 1;
  const version = state.version;
  const documentVersion = document.version;
  state.controller?.abort();
  if (state.timer) clearTimeout(state.timer);
  if (document.uri.scheme !== "file") { testProofDiagnostics.delete(document.uri); diagnosticRefreshes.delete(key); return; }
  const workspace = vscode.workspace.getWorkspaceFolder(document.uri);
  if (!workspace || workspace.uri.scheme !== "file") { testProofDiagnostics.delete(document.uri); diagnosticRefreshes.delete(key); return; }
  const root = workspace.uri.fsPath;
  const relativeFile = path.relative(root, document.uri.fsPath);
  if (!relativeFile || relativeFile.startsWith(`..${path.sep}`) || relativeFile === ".." || path.isAbsolute(relativeFile)) { testProofDiagnostics.delete(document.uri); diagnosticRefreshes.delete(key); return; }
  diagnosticRefreshes.set(key, state);
  if (!vscode.workspace.textDocuments.includes(document)) { testProofDiagnostics.delete(document.uri); return; }
  if (!vscode.workspace.isTrusted) { testProofDiagnostics.delete(document.uri); return; }
  const text = document.getText();
  if (text.length > MAX_TEST_PROOF_DOCUMENT_CHARS || Buffer.byteLength(text, "utf8") > MAX_TEST_PROOF_DOCUMENT_BYTES) {
    testProofDiagnostics.set(document.uri, [new vscode.Diagnostic(new vscode.Range(0, 0, 0, 0), `Test-proof diagnostics skipped: document exceeds ${MAX_TEST_PROOF_DOCUMENT_CHARS} characters or ${MAX_TEST_PROOF_DOCUMENT_BYTES} bytes.`, vscode.DiagnosticSeverity.Information)]);
    return;
  }
  state.controller = new AbortController();
  state.timer = setTimeout(() => { void readTestProofDiagnostics(document, root, relativeFile, state, version, documentVersion, state.controller!); }, 150);
}

function isCurrentDiagnosticRead(document: vscode.TextDocument, state: DiagnosticRefreshState, version: number, documentVersion: number, controller?: AbortController): boolean {
  return vscode.workspace.isTrusted && diagnosticRefreshes.get(document.uri.toString()) === state && state.version === version &&
    document.version === documentVersion && vscode.workspace.textDocuments.includes(document) && !controller?.signal.aborted;
}

async function readTestProofDiagnostics(document: vscode.TextDocument, root: string, relativeFile: string, state: DiagnosticRefreshState, version: number, documentVersion: number, controller: AbortController): Promise<void> {
  const diagnostics: vscode.Diagnostic[] = [];
  if (!isCurrentDiagnosticRead(document, state, version, documentVersion, controller)) return;
  const text = document.getText();
  if (text.length > MAX_TEST_PROOF_DOCUMENT_CHARS || Buffer.byteLength(text, "utf8") > MAX_TEST_PROOF_DOCUMENT_BYTES) return;
  const declarations = testDeclarations(text, document.languageId);
  for (const test of declarations) {
    if (!isCurrentDiagnosticRead(document, state, version, documentVersion, controller)) return;
    const id = testProofId(relativeFile, test.name, test.line);
    let message = "Test proof draft is missing; use the CodeLens to create an unapproved draft. No test was run.";
    try {
      const parsed = await readTestProofManifest(root, id, controller.signal) as {
        schema?: unknown; id?: unknown; approval?: { state?: unknown }; positive?: { argv?: unknown }; negative?: { argv?: unknown };
      };
      if (!isCurrentDiagnosticRead(document, state, version, documentVersion, controller)) return;
      if (parsed.schema !== "factory.e2e_proof_manifest.v1") message = "Test proof manifest schema is invalid; no proof is asserted.";
      else if (parsed.id !== id) message = "Test proof manifest identity does not match this test; no proof is asserted.";
      else if (parsed.approval?.state !== "approved" || !Array.isArray(parsed.positive?.argv) || !parsed.positive.argv.length || !Array.isArray(parsed.negative?.argv) || !parsed.negative.argv.length) {
        message = "Test proof draft is unapproved or incomplete; execution is not enabled. No test was run.";
      } else {
        message = "Manifest is configured, but this editor has no test-bound execution receipt to verify; no pass is asserted.";
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") message = "Test proof manifest is unreadable or invalid; no proof is asserted.";
    }
    diagnostics.push(new vscode.Diagnostic(
      new vscode.Range(test.line, 0, test.line, document.lineAt(test.line).text.length),
      message,
      vscode.DiagnosticSeverity.Warning,
    ));
  }
  if (declarations.length >= MAX_TEST_DECLARATIONS_PER_DOCUMENT) {
    diagnostics.push(new vscode.Diagnostic(new vscode.Range(0, 0, 0, 0), `Test-proof diagnostics are capped at ${MAX_TEST_DECLARATIONS_PER_DOCUMENT} declarations per document.`, vscode.DiagnosticSeverity.Information));
  }
  if (!isCurrentDiagnosticRead(document, state, version, documentVersion, controller)) return;
  testProofDiagnostics.set(document.uri, diagnostics);
}

async function draftTestProof(uri: vscode.Uri, line: number, testName: string): Promise<void> {
  if (!vscode.workspace.isTrusted) {
    void vscode.window.showWarningMessage("FactoryLine commands require a trusted workspace.");
    return;
  }
  const folder = uri.scheme === "file" ? vscode.workspace.getWorkspaceFolder(uri) : undefined;
  if (!folder || folder.uri.scheme !== "file") {
    void vscode.window.showWarningMessage("Open the selected test inside a trusted local workspace.");
    return;
  }
  const root = folder.uri.fsPath;
  const relativeFile = path.relative(root, uri.fsPath);
  if (!relativeFile || relativeFile.startsWith(`..${path.sep}`) || relativeFile === ".." || path.isAbsolute(relativeFile)) {
    void vscode.window.showWarningMessage("The selected test must be inside the trusted workspace.");
    return;
  }
  const id = testProofId(relativeFile, testName, line);
  const confirmed = await vscode.window.showWarningMessage(
    `Create a blank, unapproved E2E proof draft for ${path.relative(root, uri.fsPath)} :: ${testName} (line ${line + 1})? This does not discover commands, run tests, approve the proof, or assert sensitivity.`,
    { modal: true },
    "Create unapproved draft",
  );
  if (confirmed !== "Create unapproved draft") return;
  try {
    const manifest = await createUnapprovedRequirementProofDraft(root, id, relativeFile);
    void vscode.window.showInformationMessage(`Created unapproved test-proof draft: ${path.relative(root, manifest)}. Edit both command arrays and review it manually; execution is not available from this action.`);
    const document = await vscode.workspace.openTextDocument(uri);
    await refreshTestProofDiagnostics(document);
  } catch (error) {
    void vscode.window.showErrorMessage(`Could not create the test-proof draft: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function workspaceRoot(): string | undefined {
  const uri = vscode.window.activeTextEditor?.document.uri;
  const active = uri && vscode.workspace.getWorkspaceFolder(uri);
  if (active?.uri.scheme === "file") return active.uri.fsPath;
  const folders = vscode.workspace.workspaceFolders;
  return folders?.length === 1 && folders[0].uri.scheme === "file" ? folders[0].uri.fsPath : undefined;
}

function requireTrustedWorkspace(): string | undefined {
  if (!vscode.workspace.isTrusted) {
    void vscode.window.showWarningMessage("FactoryLine commands require a trusted workspace.");
    return undefined;
  }
  const root = workspaceRoot();
  if (!root) {
    void vscode.window.showWarningMessage("Open a folder before running FactoryLine.");
  }
  return root;
}

async function runFactory(root: string, args: string[]): Promise<string> {
  const configuredCommand = vscode.workspace.getConfiguration("factoryline").get<string>("command", "factory");
  const command = factoryExecutable(configuredCommand);
  output.clear();
  output.appendLine(`$ ${command} ${args.join(" ")}`);
  output.show(true);
  return vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: "FactoryLine", cancellable: true }, async (_progress, token) => {
    const controller = new AbortController();
    const cancel = token.onCancellationRequested(() => controller.abort());
    try {
      const result = await runCommand(command, args, { root, signal: controller.signal, timeoutMs: 30 * 60 * 1000, onOutput: text => output.append(text) });
      if (result.state !== "OBSERVED") throw new Error(`FactoryLine ${result.state.toLowerCase()} (exit ${result.exitCode ?? "unavailable"}).`);
      return result.stdout;
    } finally { cancel.dispose(); }
  });
}

async function offerGitHubStar(context: vscode.ExtensionContext): Promise<void> {
  const installedVersion = String(context.extension.packageJSON.version);
  const key = starPromptKey();
  if (!shouldOfferGitHubStar(context.globalState.get<string>(key), installedVersion)) {
    return;
  }
  await context.globalState.update(key, installedVersion);
  const choice = await vscode.window.showInformationMessage(
    "FactoryLine completed local work. If it clarified what is proven, you can star Code Factory to follow updates.",
    "Star Code Factory",
    "Not now",
  );
  if (choice === "Star Code Factory") {
    await vscode.env.openExternal(vscode.Uri.parse(GITHUB_REPOSITORY_URL));
  }
}

function parseMeterSnapshot(outputText: string): unknown {
  for (const line of outputText.trim().split(/\r?\n/).reverse()) {
    try {
      return JSON.parse(line);
    } catch {
      // Launcher diagnostics can precede the JSON snapshot; the final JSON line is authoritative.
    }
  }
  throw new Error("FactoryLine did not return a JSON meter snapshot.");
}

async function collectReceipts(root: string, depth = 4): Promise<string[]> {
  if (depth < 0) {
    return [];
  }
  let entries: Dirent[];
  try {
    entries = await fs.readdir(root, { withFileTypes: true });
  } catch {
    return [];
  }
  const nested = await Promise.all(entries.map(async (entry) => {
    const target = path.join(root, entry.name);
    if (entry.isDirectory()) {
      return collectReceipts(target, depth - 1);
    }
    return entry.isFile() && entry.name.endsWith(".json") ? [target] : [];
  }));
  return nested.flat();
}

async function receiptFiles(root: string): Promise<string[]> {
  const files = (await Promise.all(receiptDirectories.map((directory) => collectReceipts(path.join(root, directory))))).flat();
  const dated = await Promise.all(files.map(async (file) => ({ file, stat: await fs.stat(file) })));
  return dated.sort((left, right) => right.stat.mtimeMs - left.stat.mtimeMs).map(({ file }) => file);
}

async function showReceipt(file: string): Promise<void> {
  const raw = await fs.readFile(file, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    await vscode.window.showTextDocument(vscode.Uri.file(file));
    return;
  }
  const panel = vscode.window.createWebviewPanel("factorylineReceipt", `FactoryLine Receipt: ${path.basename(file)}`, vscode.ViewColumn.Beside, { enableScripts: false });
  panel.webview.html = receiptHtml(parsed, path.basename(file));
}

async function openLatestReceipt(): Promise<void> {
  const root = requireTrustedWorkspace();
  if (!root) {
    return;
  }
  const files = await receiptFiles(root);
  if (!files.length) {
    void vscode.window.showInformationMessage("No FactoryLine receipt JSON was found in .factory or receipts.");
    return;
  }
  const selected = await vscode.window.showQuickPick(files.map((file) => ({ label: path.basename(file), description: path.relative(root, file), file })), { title: "Open FactoryLine receipt" });
  if (selected) {
    await showReceipt(selected.file);
  }
}

async function openRequirementEvidence(requirementId: string): Promise<void> {
  const root = workspaceRoot();
  if (!root) {
    void vscode.window.showWarningMessage("Open a folder before inspecting requirement evidence.");
    return;
  }
  const matches = await findRequirementEvidence(root, requirementId);
  if (!matches.length) {
    void vscode.window.showInformationMessage(`No local proof artifact references ${requirementId}.`);
    return;
  }
  const selected = await vscode.window.showQuickPick(matches.map((match) => ({
    label: path.relative(root, match.file),
    description: `line ${match.line + 1}`,
    detail: match.preview,
    match,
  })), { title: `FactoryLine proof for ${requirementId}` });
  if (!selected) {
    return;
  }
  const document = await vscode.workspace.openTextDocument(vscode.Uri.file(selected.match.file));
  const editor = await vscode.window.showTextDocument(document, vscode.ViewColumn.Beside);
  const position = new vscode.Position(selected.match.line, 0);
  editor.selection = new vscode.Selection(position, position);
  editor.revealRange(new vscode.Range(position, position), vscode.TextEditorRevealType.InCenter);
}

async function runFeature(context: vscode.ExtensionContext, command: "assemble" | "verify"): Promise<void> {
  const root = requireTrustedWorkspace();
  if (!root) {
    return;
  }
  const feature = await vscode.window.showInputBox({ prompt: "FactoryLine feature name", validateInput: (value) => isFeatureName(value) ? undefined : "Use letters, digits, hyphens, and underscores only." });
  if (!feature) {
    return;
  }
  const before = new Set(await receiptFiles(root));
  try {
    await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: `FactoryLine ${command}: ${feature}` }, () => runFactory(root, [command, feature, "--root", root]));
    const latest = (await receiptFiles(root)).find((file) => !before.has(file)) ?? (await receiptFiles(root))[0];
    if (latest) {
      await showReceipt(latest);
    }
    void vscode.window.showInformationMessage(`FactoryLine ${command} completed for ${feature}.`);
    await offerGitHubStar(context);
  } catch (error) {
    void vscode.window.showErrorMessage(`${error instanceof Error ? error.message : String(error)} See the FactoryLine output channel.`);
  }
}

async function continueAssembly(context: vscode.ExtensionContext): Promise<void> {
  const root = requireTrustedWorkspace();
  if (!root) {
    return;
  }
  const feature = await vscode.window.showInputBox({
    prompt: "Feature name (leave blank only when exactly one feature is discoverable)",
    validateInput: (value) => !value || isFeatureName(value) ? undefined : "Use letters, digits, hyphens, and underscores only.",
  });
  if (feature === undefined) {
    return;
  }
  try {
    const args = ["continue", ...(feature ? [feature] : []), "--root", root];
    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: "FactoryLine: continue assembly" },
      () => runFactory(root, args),
    );
    void vscode.window.showInformationMessage("FactoryLine reached the next assembly boundary. See the output channel for the exact next action.");
    await offerGitHubStar(context);
  } catch (error) {
    void vscode.window.showErrorMessage(`${error instanceof Error ? error.message : String(error)} See the FactoryLine output channel.`);
  }
}

async function openMeter(): Promise<void> {
  const root = requireTrustedWorkspace();
  if (!root) {
    return;
  }
  const confirmed = await vscode.window.showWarningMessage(
    "FactoryLine will read the local meter through the configured executable in this workspace.",
    { modal: true },
    "Read local meter",
  );
  if (confirmed !== "Read local meter") {
    return;
  }
  try {
    const raw = await runFactory(root, ["meter", "--root", root, "--json"]);
    const panel = vscode.window.createWebviewPanel("factorylineMeter", "FactoryLine Meter", vscode.ViewColumn.Beside, { enableScripts: false });
    panel.webview.html = meterHtml(parseMeterSnapshot(raw));
  } catch (error) {
    void vscode.window.showErrorMessage(`${error instanceof Error ? error.message : String(error)} See the FactoryLine output channel.`);
  }
}

async function openSavings(): Promise<void> {
  const root = requireTrustedWorkspace();
  if (!root) {
    return;
  }
  const confirmed = await vscode.window.showWarningMessage(
    "FactoryLine will read aggregate-safe paired savings receipts from this workspace.",
    { modal: true },
    "Read paired savings",
  );
  if (confirmed !== "Read paired savings") {
    return;
  }
  try {
    const raw = await runFactory(root, ["savings", "report", "--root", root, "--json"]);
    const panel = vscode.window.createWebviewPanel("factorylineSavings", "FactoryLine Paired Savings", vscode.ViewColumn.Beside, { enableScripts: false });
    panel.webview.html = savingsHtml(parseMeterSnapshot(raw));
  } catch (error) {
    void vscode.window.showErrorMessage(`${error instanceof Error ? error.message : String(error)} See the FactoryLine output channel.`);
  }
}

type StudioView = "studio" | "product" | "graph";

function _studioRoute(view: StudioView, url: string): string {
  if (view === "graph") return `${url}graph-ops`;
  return view === "product" ? `${url}?mode=product` : url;
}

function _studioTitle(view: StudioView): string {
  if (view === "graph") return "Open Graph Ops";
  return view === "product" ? "Open Product Missions" : "Start Factory Studio";
}

function _markStudioIntent(view: StudioView): void {
  output.appendLine("marker: EDITOR_TRUST_CONFIRMED");
  if (view === "product") output.appendLine("marker: EDITOR_PRODUCT_MISSION_CONFIRMED");
  if (view === "graph") output.appendLine("marker: EDITOR_GRAPH_OPS_CONFIRMED");
}

async function _reuseStudio(view: StudioView): Promise<void> {
  if (studioUrl) {
    await vscode.env.openExternal(vscode.Uri.parse(_studioRoute(view, studioUrl)));
  } else {
    void vscode.window.showInformationMessage("Factory Studio is still starting. See the FactoryLine output channel.");
  }
}

function _attachStudioProcess(view: StudioView, process: childProcess.ChildProcessWithoutNullStreams): void {
  let combined = "";
  const timeout = setTimeout(() => {
    if (!studioUrl && studioProcess?.exitCode === null) {
      studioProcess.kill();
      void vscode.window.showErrorMessage("Factory Studio did not report a loopback URL within 15 seconds.");
    }
  }, 15_000);
  process.stdout.on("data", async (chunk: Buffer) => {
    const text = chunk.toString();
    combined += text;
    output.append(text);
    await _openStudioUrl(view, combined, timeout);
  });
  process.stderr.on("data", (chunk: Buffer) => output.append(chunk.toString()));
  process.on("error", error => {
    clearTimeout(timeout);
    studioProcess = undefined;
    void vscode.window.showErrorMessage(`Factory Studio failed to start: ${error.message}`);
  });
  process.on("close", code => {
    clearTimeout(timeout);
    studioProcess = undefined;
    studioUrl = undefined;
    if (code && code !== 0) void vscode.window.showErrorMessage(`Factory Studio exited with ${code}. See the FactoryLine output channel.`);
  });
}

async function _openStudioUrl(view: StudioView, combined: string, timeout: NodeJS.Timeout): Promise<void> {
  const parsed = factoryStudioUrl(combined);
  if (studioUrl || !parsed) return;
  studioUrl = parsed;
  clearTimeout(timeout);
  const opened = await vscode.env.openExternal(vscode.Uri.parse(_studioRoute(view, parsed)));
  if (!opened) void vscode.window.showWarningMessage(`Factory Studio is running at ${parsed}`);
}

function _startStudio(root: string, view: StudioView): void {
  const configuredCommand = vscode.workspace.getConfiguration("factoryline").get<string>("command", "factory");
  const command = factoryExecutable(configuredCommand);
  const args = ["studio", "--root", root, "--port", "0", "--no-browser"];
  output.clear();
  _markStudioIntent(view);
  output.appendLine(`$ ${command} studio --root <workspace> --port 0 --no-browser`);
  output.show(true);
  studioUrl = undefined;
  studioProcess = childProcess.spawn(command, args, { cwd: root, shell: false });
  _attachStudioProcess(view, studioProcess);
}

async function openFactoryStudio(view: StudioView = "studio"): Promise<void> {
  const productMode = view === "product";
  const graphMode = view === "graph";
  const title = _studioTitle(view);
  const root = requireTrustedWorkspace();
  if (!root) {
    return;
  }
  const confirmed = await vscode.window.showWarningMessage(
    `${title} on loopback for this workspace? Graph Ops only inspects local artifacts; Studio grants no execute, merge, deploy, publish, credential, connector, or external-message authority.`,
    { modal: true },
    "Start local Studio",
  );
  if (confirmed !== "Start local Studio") {
    return;
  }
  _markStudioIntent(view);
  if (studioProcess && studioProcess.exitCode === null) {
    await _reuseStudio(view);
    return;
  }
  _startStudio(root, view);
}

export function activate(context: vscode.ExtensionContext): void {
  registerEvidence(context);
  registerScanOnSave(context);
  vscode.workspace.textDocuments.forEach(document => refreshTestProofDiagnostics(document));
  context.subscriptions.push(
    output,
    testProofDiagnostics,
    vscode.languages.registerCodeLensProvider({ scheme: "file" }, new RequirementCodeLensProvider()),
    vscode.workspace.onDidOpenTextDocument(document => refreshTestProofDiagnostics(document)),
    vscode.workspace.onDidChangeTextDocument(event => refreshTestProofDiagnostics(event.document)),
    vscode.workspace.onDidCloseTextDocument(document => { const key = document.uri.toString(); const state = diagnosticRefreshes.get(key); state?.controller?.abort(); if (state?.timer) clearTimeout(state.timer); diagnosticRefreshes.delete(key); testProofDiagnostics.delete(document.uri); }),
    vscode.workspace.onDidGrantWorkspaceTrust(() => vscode.workspace.textDocuments.forEach(document => refreshTestProofDiagnostics(document))),
    { dispose: () => { for (const [key, state] of diagnosticRefreshes) { state.controller?.abort(); if (state.timer) clearTimeout(state.timer); diagnosticRefreshes.delete(key); } } },
    vscode.commands.registerCommand("factoryline.assemble", () => runFeature(context, "assemble")),
    vscode.commands.registerCommand("factoryline.continue", () => continueAssembly(context)),
    vscode.commands.registerCommand("factoryline.verify", () => runFeature(context, "verify")),
    vscode.commands.registerCommand("factoryline.openMeter", openMeter),
    vscode.commands.registerCommand("factoryline.openSavings", openSavings),
    vscode.commands.registerCommand("factoryline.openLatestReceipt", openLatestReceipt),
    vscode.commands.registerCommand("factoryline.openStudio", () => openFactoryStudio()),
    vscode.commands.registerCommand("factoryline.openProductMissions", () => openFactoryStudio("product")),
    vscode.commands.registerCommand("factoryline.openGraphOps", () => openFactoryStudio("graph")),
    vscode.commands.registerCommand("factoryline.openRequirementEvidence", openRequirementEvidence),
    vscode.commands.registerCommand("factoryline.draftTestProof", draftTestProof),
    { dispose: () => { if (studioProcess?.exitCode === null) { studioProcess.kill(); } } },
  );
}

export function deactivate(): void {
  if (studioProcess?.exitCode === null) {
    studioProcess.kill();
  }
  output.dispose();
}
