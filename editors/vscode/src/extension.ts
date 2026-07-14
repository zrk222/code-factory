import * as childProcess from "node:child_process";
import { type Dirent } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as vscode from "vscode";
import { receiptHtml } from "./receipt";
import { factoryExecutable, isFeatureName } from "./runner";

const output = vscode.window.createOutputChannel("FactoryLine");
const receiptDirectories = [".factory", "receipts"];

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

async function runFactory(root: string, args: string[]): Promise<void> {
  const configuredCommand = vscode.workspace.getConfiguration("factoryline").get<string>("command", "factory");
  const command = factoryExecutable(configuredCommand);
  output.clear();
  output.appendLine(`$ ${command} ${args.join(" ")}`);
  output.show(true);
  await new Promise<void>((resolve, reject) => {
    const child = childProcess.spawn(command, args, {
      cwd: root,
      shell: false,
    });
    child.stdout.on("data", (chunk: Buffer) => output.append(chunk.toString()));
    child.stderr.on("data", (chunk: Buffer) => output.append(chunk.toString()));
    child.on("error", reject);
    child.on("close", (code) => code === 0 ? resolve() : reject(new Error(`FactoryLine exited with ${code ?? "an unknown error"}.`)));
  });
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

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    output,
    vscode.commands.registerCommand("factoryline.assemble", () => runFeature("assemble")),
    vscode.commands.registerCommand("factoryline.verify", () => runFeature("verify")),
    vscode.commands.registerCommand("factoryline.openLatestReceipt", openLatestReceipt),
  );
}

export function deactivate(): void {
  output.dispose();
}
