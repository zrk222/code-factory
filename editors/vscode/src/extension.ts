import * as childProcess from "node:child_process";
import { type Dirent } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as vscode from "vscode";
import { receiptHtml } from "./receipt";
import { meterHtml } from "./meter";
import { factoryExecutable, factoryStudioUrl, isFeatureName } from "./runner";

const output = vscode.window.createOutputChannel("FactoryLine");
const receiptDirectories = [".factory", "receipts"];
let studioProcess: childProcess.ChildProcessWithoutNullStreams | undefined;
let studioUrl: string | undefined;

function workspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
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
  return new Promise<string>((resolve, reject) => {
    let combined = "";
    const child = childProcess.spawn(command, args, {
      cwd: root,
      shell: false,
    });
    child.stdout.on("data", (chunk: Buffer) => { const text = chunk.toString(); combined += text; output.append(text); });
    child.stderr.on("data", (chunk: Buffer) => { const text = chunk.toString(); combined += text; output.append(text); });
    child.on("error", reject);
    child.on("close", (code) => code === 0 ? resolve(combined) : reject(new Error(`FactoryLine exited with ${code ?? "an unknown error"}.`)));
  });
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

async function runFeature(command: "assemble" | "verify"): Promise<void> {
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

async function openFactoryStudio(): Promise<void> {
  const root = requireTrustedWorkspace();
  if (!root) {
    return;
  }
  const confirmed = await vscode.window.showWarningMessage(
    "Start Factory Studio on loopback for this workspace? It may create new child directories, but cannot deploy, publish, sign, inject credentials, grant connectors, or send external messages.",
    { modal: true },
    "Start local Studio",
  );
  if (confirmed !== "Start local Studio") {
    return;
  }
  output.appendLine("marker: EDITOR_TRUST_CONFIRMED");
  if (studioProcess && studioProcess.exitCode === null) {
    if (studioUrl) {
      await vscode.env.openExternal(vscode.Uri.parse(studioUrl));
    } else {
      void vscode.window.showInformationMessage("Factory Studio is still starting. See the FactoryLine output channel.");
    }
    return;
  }

  const configuredCommand = vscode.workspace.getConfiguration("factoryline").get<string>("command", "factory");
  const command = factoryExecutable(configuredCommand);
  const args = ["studio", "--root", root, "--port", "0", "--no-browser"];
  output.clear();
  output.appendLine("marker: EDITOR_TRUST_CONFIRMED");
  output.appendLine(`$ ${command} studio --root <workspace> --port 0 --no-browser`);
  output.show(true);
  studioUrl = undefined;
  let combined = "";
  studioProcess = childProcess.spawn(command, args, { cwd: root, shell: false });
  const timeout = setTimeout(() => {
    if (!studioUrl && studioProcess?.exitCode === null) {
      studioProcess.kill();
      void vscode.window.showErrorMessage("Factory Studio did not report a loopback URL within 15 seconds.");
    }
  }, 15_000);
  studioProcess.stdout.on("data", async (chunk: Buffer) => {
    const text = chunk.toString();
    combined += text;
    output.append(text);
    const parsed = factoryStudioUrl(combined);
    if (!studioUrl && parsed) {
      studioUrl = parsed;
      clearTimeout(timeout);
      const opened = await vscode.env.openExternal(vscode.Uri.parse(parsed));
      if (!opened) {
        void vscode.window.showWarningMessage(`Factory Studio is running at ${parsed}`);
      }
    }
  });
  studioProcess.stderr.on("data", (chunk: Buffer) => output.append(chunk.toString()));
  studioProcess.on("error", (error) => {
    clearTimeout(timeout);
    studioProcess = undefined;
    void vscode.window.showErrorMessage(`Factory Studio failed to start: ${error.message}`);
  });
  studioProcess.on("close", (code) => {
    clearTimeout(timeout);
    studioProcess = undefined;
    studioUrl = undefined;
    if (code && code !== 0) {
      void vscode.window.showErrorMessage(`Factory Studio exited with ${code}. See the FactoryLine output channel.`);
    }
  });
}

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    output,
    vscode.commands.registerCommand("factoryline.assemble", () => runFeature("assemble")),
    vscode.commands.registerCommand("factoryline.verify", () => runFeature("verify")),
    vscode.commands.registerCommand("factoryline.openMeter", openMeter),
    vscode.commands.registerCommand("factoryline.openLatestReceipt", openLatestReceipt),
    vscode.commands.registerCommand("factoryline.openStudio", openFactoryStudio),
    { dispose: () => { if (studioProcess?.exitCode === null) { studioProcess.kill(); } } },
  );
}

export function deactivate(): void {
  if (studioProcess?.exitCode === null) {
    studioProcess.kill();
  }
  output.dispose();
}
