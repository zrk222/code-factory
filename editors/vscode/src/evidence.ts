import * as path from "node:path";
import { realpath } from "node:fs/promises";
import * as vscode from "vscode";
import { LANES, Lane, Result, audit, findings, redact, summary } from "@factoryline/proof-client";

type Row = { label: string; description?: string; detail: string; result?: Result; child?: boolean; location?: { root: string; path: string; line?: number } };

class EvidenceView implements vscode.TreeDataProvider<Row>, vscode.Disposable {
  private readonly changed = new vscode.EventEmitter<Row | undefined>();
  readonly onDidChangeTreeData = this.changed.event;
  private readonly results = new Map<string, Result[]>();
  private readonly stale = new Set<string>();
  private readonly running = new Map<string, AbortController>();
  private selected?: vscode.WorkspaceFolder;

  dispose(): void { for (const run of this.running.values()) run.abort(); this.changed.dispose(); }

  getTreeItem(row: Row): vscode.TreeItem {
    const item = new vscode.TreeItem(row.label, row.result && !row.child ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None);
    item.description = row.description;
    item.tooltip = row.detail;
    if (row.result && !row.child) item.command = { command: "factoryline.inspectAudit", title: "Inspect audit report", arguments: [row.result] };
    if (row.location) item.command = { command: "factoryline.openAuditFinding", title: "Open audit finding", arguments: [row.location] };
    return item;
  }

  getChildren(row?: Row): Row[] {
    if (row?.result) return this.findingRows(row.result);
    return this.laneRows();
  }

  private findingRows(result: Result): Row[] {
    return findings(result).map(item => ({ label: item.message, description: item.severity, detail: item.path ? `${item.path}${item.line ? `:${item.line}` : ""}` : "Location not supplied by this audit", child: true,
      location: item.path && this.selected ? { root: this.selected.uri.fsPath, path: item.path, line: item.line } : undefined }));
  }

  private laneRows(): Row[] {
    const key = this.selected?.uri.toString();
    const observed = key ? this.results.get(key) || [] : [];
    const rows: Row[] = [{ label: this.selected?.name || "Select a workspace with Run CF + ForgeLine", detail: "Local observations; candidate binding remains UNBOUND." }];
    for (const lane of Object.keys(LANES) as Lane[]) rows.push(this.laneRow(lane, observed, key));
    return rows;
  }

  private laneRow(lane: Lane, observed: Result[], key?: string): Row {
    const result = observed.find(item => item.lane === lane);
    return { label: LANES[lane].label, description: result ? (key && this.stale.has(key) ? "STALE" : result.state) : "NOT_RUN", detail: result ? `${result.detail}\n${result.limit}` : LANES[lane].limit, result };
  }

  invalidate(uri: vscode.Uri): void {
    const folder = vscode.workspace.getWorkspaceFolder(uri);
    if (!folder) return;
    const key = folder.uri.toString();
    if (this.results.has(key) || this.running.has(key)) { this.stale.add(key); this.changed.fire(undefined); }
  }

  async selectWorkspace(): Promise<vscode.WorkspaceFolder | undefined> {
    const folders = vscode.workspace.workspaceFolders || [];
    if (folders.length === 1) return folders[0];
    return vscode.window.showWorkspaceFolderPick({ placeHolder: "Choose the workspace to audit" });
  }

  async run(): Promise<void> {
    if (!vscode.workspace.isTrusted) { void vscode.window.showWarningMessage("Trust this workspace before running CF or ForgeLine."); return; }
    const folder = await this.selectWorkspace();
    if (!folder) return;
    if (folder.uri.scheme !== "file") { void vscode.window.showWarningMessage("Audit execution needs a filesystem workspace in the local or remote extension host."); return; }
    const key = folder.uri.toString();
    if (this.running.has(key)) { void vscode.window.showInformationMessage("An audit is already running for this workspace."); return; }
    const selection = await vscode.window.showQuickPick([{ label: "Run CF + ForgeLine", lane: "all" }, ...Object.entries(LANES).map(([lane, item]) => ({ label: item.label, lane }))], { title: "Choose local audit scope" });
    if (!selection) return;
    const yes = await vscode.window.showWarningMessage(`Run ${selection.label} in ${folder.name}? Configured local executables will run. ForgeLine may write its local inventory report.`, { modal: true }, "Run audit");
    if (yes !== "Run audit") return;
    this.selected = folder;
    const controller = new AbortController();
    this.running.set(key, controller);
    // Clear old results so unselected lanes cannot be presented as fresh.
    this.results.set(key, []); this.stale.delete(key); this.changed.fire(undefined);
    try {
      await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: `FactoryLine · ${folder.name}`, cancellable: true }, async (progress, token) => {
        const cancel = token.onCancellationRequested(() => controller.abort());
        try { await this.collect(folder, selection.lane, controller, message => progress.report({ message })); }
        finally { cancel.dispose(); }
      });
    } catch (error) { void vscode.window.showErrorMessage(`Audit could not complete: ${redact(String(error))}`); }
    finally { this.running.delete(key); this.changed.fire(undefined); }
  }

  private async collect(folder: vscode.WorkspaceFolder, selection: string, controller: AbortController, progress: (text: string) => void): Promise<void> {
    const config = vscode.workspace.getConfiguration("factoryline", folder.uri);
    const lanes = selection === "all" ? Object.keys(LANES) as Lane[] : [selection as Lane];
    for (const lane of lanes) {
      if (controller.signal.aborted) break;
      progress(LANES[lane].label);
      const result = await audit(folder.uri.fsPath, lane, { factory: config.get<string>("command", "factory"), forge: config.get<string>("forgeCommand", "forge"), signal: controller.signal });
      this.results.get(folder.uri.toString())!.push(result);
      this.changed.fire(undefined);
    }
  }

  async copySummary(): Promise<void> {
    const key = this.selected?.uri.toString();
    const text = summary(key ? this.results.get(key) || [] : [], key ? this.stale.has(key) : false);
    await vscode.env.clipboard.writeText(text);
    void vscode.window.showInformationMessage("CF and ForgeLine results copied, including missing checks and scope limits.");
  }

  forgetRemoved(): void {
    const active = new Set(vscode.workspace.workspaceFolders?.map(folder => folder.uri.toString()));
    for (const key of this.results.keys()) if (!active.has(key)) { this.running.get(key)?.abort(); this.results.delete(key); this.stale.delete(key); }
    if (this.selected && !active.has(this.selected.uri.toString())) this.selected = undefined;
    this.changed.fire(undefined);
  }
}

export function registerEvidence(context: vscode.ExtensionContext): void {
  const view = new EvidenceView();
  const watcher = vscode.workspace.createFileSystemWatcher("**/*");
  const invalidate = (uri: vscode.Uri) => {
    // Audit-generated receipts must not invalidate their own observation run.
    const folder = vscode.workspace.getWorkspaceFolder(uri);
    const rel = folder ? path.relative(folder.uri.fsPath, uri.fsPath).replace(/\\/g, "/") : "";
    if (!/^(?:\.factory|\.forge|node_modules|\.git\/objects)(?:\/|$)/.test(rel)) view.invalidate(uri);
  };
  context.subscriptions.push(view, watcher,
    vscode.window.registerTreeDataProvider("factorylineEvidence", view),
    vscode.commands.registerCommand("factoryline.auditWorkspace", () => view.run()),
    vscode.commands.registerCommand("factoryline.copyAuditSummary", () => view.copySummary()),
    vscode.commands.registerCommand("factoryline.inspectAudit", async (result: Result) => {
      if (!result?.lane || !Object.prototype.hasOwnProperty.call(LANES, result.lane)) return;
      const document = await vscode.workspace.openTextDocument({ language: "json", content: redact(JSON.stringify(result, null, 2)) });
      await vscode.window.showTextDocument(document, { preview: true });
    }),
    vscode.commands.registerCommand("factoryline.openAuditFinding", async (location: { root: string; path: string; line?: number }) => {
      if (!location || typeof location.root !== "string" || typeof location.path !== "string") return;
      const root = path.resolve(location.root);
      const target = path.resolve(root, location.path);
      if (target === root || !target.startsWith(root + path.sep)) {
        void vscode.window.showWarningMessage("Finding path is outside the audited workspace.");
        return;
      }
      const [actualRoot, actualTarget] = await Promise.all([realpath(root), realpath(target)]);
      if (!actualTarget.startsWith(actualRoot + path.sep)) {
        void vscode.window.showWarningMessage("Finding resolves outside the audited workspace.");
        return;
      }
      const line = Math.max(0, (location.line || 1) - 1);
      await vscode.window.showTextDocument(vscode.Uri.file(target), { preview: true, selection: new vscode.Range(line, 0, line, 0) });
    }),
    watcher.onDidChange(invalidate), watcher.onDidCreate(invalidate), watcher.onDidDelete(invalidate),
    vscode.workspace.onDidChangeTextDocument(event => invalidate(event.document.uri)),
    vscode.workspace.onDidChangeWorkspaceFolders(() => view.forgetRemoved()),
  );
}
