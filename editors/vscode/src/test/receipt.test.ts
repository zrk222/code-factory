import * as assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";
import { escapeHtml, receiptHtml, summarizeReceipt } from "../receipt";
import { factoryExecutable, factoryStudioUrl, isFeatureName } from "../runner";
import { meterHtml, savingsHtml } from "../meter";
import { createUnapprovedRequirementProofDraft, findRequirementEvidence, isRequirementId, MAX_TEST_DECLARATIONS_PER_DOCUMENT, MAX_TEST_PROOF_MANIFEST_BYTES, readTestProofManifest, requirementIds, requirementProofManifestPath, testDeclarations, testProofId } from "../requirement";
import { scanCompleted, scanDiagnosticSpecs, singleFileScanArgs } from "../scan";
import { GITHUB_REPOSITORY_URL, shouldOfferGitHubStar, starPromptKey } from "../star_prompt";

const receipt = {
  schema: "factory.trace.v1",
  feature: "editor-layer",
  rollup: { verdict: "SHIPPABLE" },
  stage: "evidence",
};

assert.deepEqual(summarizeReceipt(receipt), {
  schema: "factory.trace.v1",
  feature: "editor-layer",
  verdict: "SHIPPABLE",
  stage: "evidence",
});
assert.equal(escapeHtml(`<receipt & "proof">`), "&lt;receipt &amp; &quot;proof&quot;&gt;");
assert.match(receiptHtml(receipt, "receipt <panel>"), /receipt &lt;panel&gt;/);
assert.match(receiptHtml(receipt, "receipt"), /SHIPPABLE/);
assert.equal(factoryExecutable("factory", "win32"), "factory.exe");
assert.equal(factoryExecutable("C:\\tools\\factory.exe", "win32"), "C:\\tools\\factory.exe");
assert.equal(factoryExecutable("factory", "linux"), "factory");
assert.match(meterHtml({ summary: { stages_measured: 2, build_wall_ms: 10, tokens_reported_by_modules: false }, activity: { stages_successful: 2, latest_stage: { module: "hsf", stage: "compile", ok: true } } }), /not reported by modules/);
assert.match(meterHtml({ summary: { flow: { agent_ms: { value: 12, known: 1, unknown: 0 }, first_pass_gate_rate: { value: 1, known: 1, unknown: 0 }, token_quality: { exact: 1, estimated: 0, unknown: 0 } } }, activity: {} }), /Agent time/);
assert.match(meterHtml({ summary: { flow: { agent_ms: { value: 12, known: 1, unknown: 0 }, first_pass_gate_rate: { value: 1, known: 1, unknown: 0 }, token_quality: { exact: 1, estimated: 0, unknown: 0 } } }, activity: {} }), /100.0%/);
assert.match(savingsHtml({ pairs: 2, time: { saved_total: 100, weighted_savings_rate: 0.25 }, tokens: { saved_total: -4, weighted_savings_rate: -0.1 }, cost_usd: { saved_total: null }, productivity: { gain_rate: null, coverage_rate: 0 } }), /100 ms/);
assert.match(savingsHtml({ pairs: 2, time: { saved_total: 100, weighted_savings_rate: 0.25 }, tokens: { saved_total: -4, weighted_savings_rate: -0.1 }, cost_usd: { saved_total: null }, productivity: { gain_rate: null, coverage_rate: 0 } }), /-4/);
assert.match(savingsHtml({ pairs: 2, time: {}, tokens: {}, cost_usd: {}, productivity: { gain_rate: null } }), /withheld until equivalent-outcome proof/);
assert.equal(isFeatureName("editor-layer_1"), true);
assert.equal(isFeatureName("editor layer; rm"), false);
assert.equal(factoryStudioUrl("marker: STUDIO_STARTED\nFactory Studio: http://127.0.0.1:43117/\n"), "http://127.0.0.1:43117/");
assert.equal(factoryStudioUrl("Factory Studio: http://0.0.0.0:43117/"), undefined);
assert.deepEqual(requirementIds("FR-101 maps to NFR-A11Y and FR-101."), ["FR-101", "NFR-A11Y"]);
assert.deepEqual(testDeclarations("def test_one():\nasync def test_two():\n", "python"), [
  { line: 0, name: "test_one" }, { line: 1, name: "test_two" },
]);
assert.deepEqual(testDeclarations("test('works', fn);\nit(\"also works\", fn);\ntest(name, fn);", "typescript"), [
  { line: 0, name: "works" }, { line: 1, name: "also works" },
]);
assert.deepEqual(testDeclarations("describe('suite', fn);", "ruby"), []);
assert.match(testProofId("tests/a.py", "test good"), /^test-test-good-line-0-[a-f0-9]{16}$/);
assert.notEqual(testProofId("tests/a.py", "test good", 1), testProofId("tests/a.py", "test good", 2));
test("isRequirementId accepts safe IDs", function isRequirementIdTest() {
  assert.equal(isRequirementId("REQ-TRACE_7"), true);
  assert.equal(isRequirementId("../outside"), false);
  assert.equal(isRequirementId(""), false);
});
test("requirementProofManifestPath rejects path syntax", function requirementProofManifestPathTest() {
  assert.equal(requirementProofManifestPath("/workspace", "REQ-TRACE_7"), path.join("/workspace", ".factory", "requirement-proofs", "REQ-TRACE_7", "e2e-manifest.json"));
  assert.throws(() => requirementProofManifestPath("/workspace", "../outside"), /Invalid requirement identifier/);
});
test("readTestProofManifest reads a bounded regular manifest", async function readTestProofManifestTest() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "cf-proof-read-"));
  try {
    const manifest = requirementProofManifestPath(root, "REQ-READ-1");
    await fs.mkdir(path.dirname(manifest), { recursive: true });
    await fs.writeFile(manifest, JSON.stringify({ id: "REQ-READ-1" }), { mode: 0o600 });
    assert.deepEqual(await readTestProofManifest(root, "REQ-READ-1"), { id: "REQ-READ-1" });
    await assert.rejects(readTestProofManifest(root, "../outside"), /Invalid proof identifier/);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
test("readTestProofManifest checks pre-abort before starting filesystem work", async function preAbortedProofReadTest() {
  const api = require("node:fs/promises") as { realpath: typeof fs.realpath };
  const original = api.realpath;
  let calls = 0;
  api.realpath = (async () => { calls += 1; throw new Error("unexpected filesystem access"); }) as typeof api.realpath;
  const controller = new AbortController(); controller.abort();
  try {
    await assert.rejects(readTestProofManifest(path.join(os.tmpdir(), "missing-proof-workspace"), "REQ-ABORT-1", controller.signal), /cancelled/);
    assert.equal(calls, 0);
  } finally { api.realpath = original; }
});
assert.equal(testDeclarations(Array.from({ length: MAX_TEST_DECLARATIONS_PER_DOCUMENT + 1 }, (_, i) => `def test_${i}():`).join("\n"), "python").length, MAX_TEST_DECLARATIONS_PER_DOCUMENT);
assert.deepEqual(testDeclarations("def test_oversized():\n" + "x".repeat(MAX_TEST_PROOF_MANIFEST_BYTES * 33), "python"), []);
assert.deepEqual(testDeclarations("def test_multibyte():\n" + "漢".repeat(800_000), "python"), []);
const requirementChecks = (async () => {
const requirementRoot = await fs.mkdtemp(path.join(os.tmpdir(), "cf-requirement-"));
try {
  await fs.mkdir(path.join(requirementRoot, ".factory", "nested"), { recursive: true });
  await fs.mkdir(path.join(requirementRoot, "tests"), { recursive: true });
  await fs.mkdir(path.join(requirementRoot, "node_modules", "tests"), { recursive: true });
  await fs.writeFile(path.join(requirementRoot, ".factory", "nested", "contract.json"), '{"requirement":"REQ-TRACE-7"}\n');
  await fs.writeFile(path.join(requirementRoot, "tests", "case.md"), "first line\nREQ-TRACE-7 is asserted here\n");
  await fs.writeFile(path.join(requirementRoot, "tests", "large.txt"), `REQ-TRACE-7 ${"x".repeat(2_000_001)}`);
  await fs.writeFile(path.join(requirementRoot, "node_modules", "tests", "ignored.md"), "REQ-TRACE-7");
  const matches = await findRequirementEvidence(requirementRoot, "REQ-TRACE-7");
  assert.deepEqual(matches.map(({ file, line }) => [path.relative(requirementRoot, file), line]), [
    [path.join(".factory", "nested", "contract.json"), 0],
    [path.join("tests", "case.md"), 1],
  ]);
  assert.match(matches[1].preview, /is asserted here/);
  const draftId = testProofId("tests/case.md", "test sensitive behavior");
  const draftPath = await createUnapprovedRequirementProofDraft(requirementRoot, draftId, "tests/case.md");
  assert.equal((await readTestProofManifest(requirementRoot, draftId)).id, draftId);
  const fileApi = require("node:fs/promises") as { open: typeof fs.open };
  const open = fileApi.open;
  const cancelled = new AbortController();
  const captured: { handle?: Awaited<ReturnType<typeof fs.open>> } = {};
  fileApi.open = async (...args) => {
    const handle = await open(...args);
    captured.handle = handle;
    cancelled.abort();
    return handle;
  };
  try {
    await assert.rejects(readTestProofManifest(requirementRoot, draftId, cancelled.signal), /cancelled/);
    assert.ok(captured.handle);
    await assert.rejects(captured.handle.stat(), { code: "EBADF" });
  } finally {
    fileApi.open = open;
  }
  const draft = JSON.parse(await fs.readFile(draftPath, "utf8"));
  assert.deepEqual(draft, {
    schema: "factory.e2e_proof_manifest.v1",
    id: draftId,
    approval: { state: "unapproved", approved_by: "" },
    working_directory: ".",
    timeout_seconds: 120,
    network_egress: "not_granted",
    positive: { argv: [] },
    negative: { argv: [] },
    artifact_paths: ["tests/case.md"],
  });
  await assert.rejects(createUnapprovedRequirementProofDraft(requirementRoot, draftId, "tests/case.md"), { code: "EEXIST" });
  await assert.rejects(createUnapprovedRequirementProofDraft(requirementRoot, testProofId("tests/case.md", "linked"), "../outside.py"), /inside the workspace/);
  await fs.writeFile(draftPath, "not-json");
  await assert.rejects(readTestProofManifest(requirementRoot, draftId), SyntaxError);
  const oversizedId = testProofId("tests/case.md", "oversized");
  const oversizedDir = path.join(requirementRoot, ".factory", "requirement-proofs", oversizedId);
  await fs.mkdir(oversizedDir, { recursive: true });
  await fs.writeFile(path.join(oversizedDir, "e2e-manifest.json"), " ".repeat(MAX_TEST_PROOF_MANIFEST_BYTES + 1));
  await assert.rejects(readTestProofManifest(requirementRoot, oversizedId), /bounded regular single-link/);
  const linkedRoot = await fs.mkdtemp(path.join(os.tmpdir(), "cf-requirement-linked-"));
  const outsideProofs = await fs.mkdtemp(path.join(os.tmpdir(), "cf-requirement-outside-"));
  try {
    await fs.mkdir(path.join(linkedRoot, ".factory"));
    await fs.symlink(outsideProofs, path.join(linkedRoot, ".factory", "requirement-proofs"), "junction");
    await assert.rejects(readTestProofManifest(linkedRoot, draftId), /linked or non-directory/);
  } catch (error) {
    if (!(["EPERM", "EACCES", "ENOTSUP"].includes((error as NodeJS.ErrnoException).code ?? ""))) throw error;
  } finally {
    await fs.rm(linkedRoot, { recursive: true, force: true });
    await fs.rm(outsideProofs, { recursive: true, force: true });
  }
} finally {
  await fs.rm(requirementRoot, { recursive: true, force: true });
}
assert.equal(starPromptKey(), "factoryline.githubStarPromptedVersion");
assert.equal(shouldOfferGitHubStar(undefined, "0.8.1"), true);
assert.equal(shouldOfferGitHubStar("0.8.1", "0.8.1"), false);
assert.equal(shouldOfferGitHubStar("0.8.0", "0.8.1"), true);
assert.equal(GITHUB_REPOSITORY_URL, "https://github.com/zrk222/code-factory");
})();

const moduleLoader = require("node:module") as {
  _load: (request: string, parent: unknown, isMain: boolean) => unknown;
};
const fsPromises = require("node:fs/promises") as {
  realpath: (target: string) => Promise<string>;
};
const originalLoad = moduleLoader._load;
const originalRealpath = fsPromises.realpath;
const registeredCommands = new Map<string, (...args: unknown[]) => unknown>();
const warningMessages: string[] = [];
const registeredProviders: string[] = [];
const workspaceEvents = new Map<string, (value?: any) => void>();
const diagnosticEntries = new Map<string, unknown[]>();
let workspaceTrusted = true;
let activeDocument: any;
const workspaceRoot = path.resolve(os.tmpdir(), "cf-evidence");
let openedDocuments = 0;
let disposedResources = 0;
const disposable = { dispose() { disposedResources += 1; } };
const outputChannel = { dispose() { disposedResources += 1; } };
class FakeEventEmitter {
  event = () => disposable;
  fire() {}
  dispose() {}
}
const fakeWatcher = {
  onDidChange: () => disposable,
  onDidCreate: () => disposable,
  onDidDelete: () => disposable,
};
const fakeVscode = {
  EventEmitter: FakeEventEmitter,
  workspace: {
    createFileSystemWatcher: () => fakeWatcher,
    onDidChangeTextDocument: (handler: (event: any) => void) => { workspaceEvents.set("change", handler); return disposable; },
    onDidChangeWorkspaceFolders: () => disposable,
    onDidOpenTextDocument: (handler: (document: any) => void) => { workspaceEvents.set("open", handler); return disposable; },
    onDidCloseTextDocument: (handler: (document: any) => void) => { workspaceEvents.set("close", handler); return disposable; },
    onDidSaveTextDocument: (handler: (document: any) => void) => { workspaceEvents.set("save", handler); return disposable; },
    getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }),
    onDidGrantWorkspaceTrust: (handler: () => void) => { workspaceEvents.set("trust", handler); return disposable; },
    textDocuments: [],
    get isTrusted() { return workspaceTrusted; },
    getWorkspaceFolder: (uri: any) => uri.scheme === "file" ? { uri: { scheme: "file", fsPath: workspaceRoot } } : undefined,
  },
  window: {
    createOutputChannel: () => outputChannel,
    registerTreeDataProvider: (id: string) => { registeredProviders.push(id); return disposable; },
    showWarningMessage: async (message: string) => { warningMessages.push(message); return undefined; },
    showTextDocument: async () => { openedDocuments += 1; },
    get activeTextEditor() { return activeDocument ? { document: activeDocument } : undefined; },
  },
  commands: {
    registerCommand: (name: string, callback: (...args: unknown[]) => unknown) => {
      registeredCommands.set(name, callback);
      return disposable;
    },
  },
  languages: {
    registerCodeLensProvider: () => disposable,
    createDiagnosticCollection: () => ({
      set: (uri: any, diagnostics: unknown[]) => diagnosticEntries.set(uri.toString(), diagnostics),
      delete: (uri: any) => diagnosticEntries.delete(uri.toString()),
      dispose() { disposedResources += 1; },
    }),
  },
  Diagnostic: class { constructor(..._args: unknown[]) {} },
  DiagnosticSeverity: { Warning: 2, Information: 3 },
  Uri: { file: (fsPath: string) => ({ scheme: "file", fsPath, toString: () => `file://${fsPath}` }) },
  CodeLens: class { constructor(..._args: unknown[]) {} },
  Range: class { constructor(..._args: unknown[]) {} },
};
void (async () => {
  await requirementChecks;
  moduleLoader._load = function (request, parent, isMain) {
    return request === "vscode" ? fakeVscode : originalLoad.call(this, request, parent, isMain);
  };
  const root = path.resolve(os.tmpdir(), "cf-evidence");
  const inRootFinding = path.join(root, "src", "finding.ts");
  const outsideFinding = path.resolve(os.tmpdir(), "cf-outside", "secret.ts");
  fsPromises.realpath = async target => {
    const resolved = path.resolve(target);
    if (resolved === root) return root;
    if (resolved === inRootFinding) return outsideFinding;
    return originalRealpath(target);
  };
  try {
    const { registerEvidence } = require("../evidence") as {
      registerEvidence: (context: { subscriptions: unknown[] }) => void;
    };
    const subscriptions: unknown[] = [];
    registerEvidence({ subscriptions });
    assert.ok(subscriptions.length >= 7);
    assert.deepEqual([...registeredCommands.keys()], [
      "factoryline.auditWorkspace",
      "factoryline.copyAuditSummary",
      "factoryline.inspectAudit",
      "factoryline.openAuditFinding",
    ]);
    const openAuditFinding = registeredCommands.get("factoryline.openAuditFinding") as
      | ((location: { root: string; path: string }) => Promise<unknown>)
      | undefined;
    assert.ok(openAuditFinding);

    await openAuditFinding({ root, path: path.join("..", "secret.txt") });
    assert.match(warningMessages.at(-1) || "", /outside the audited workspace/);
    await openAuditFinding({ root, path: path.join("src", "finding.ts") });
    assert.match(warningMessages.at(-1) || "", /resolves outside the audited workspace/);
    assert.equal(openedDocuments, 0);

    const { activate, deactivate } = require("../extension") as {
      activate: (context: { subscriptions: unknown[] }) => void;
      deactivate: () => void;
    };
    const docPath = path.join(root, "tests", "event-lifecycle.test.py");
    const docUri = { scheme: "file", fsPath: docPath, toString: () => `file://${docPath}` };
    const doc = { uri: docUri, languageId: "python", version: 1, getText: () => "def test_lifecycle():\n    pass\n", lineAt: () => ({ text: "def test_lifecycle():" }) };
    (fakeVscode.workspace.textDocuments as unknown[]).push(doc);
    activeDocument = doc;
    const context = { subscriptions: [] as unknown[] };
    activate(context);
    assert.ok(registeredProviders.includes("factorylineEvidence"));
    assert.ok(registeredCommands.has("factoryline.assemble"));
    assert.ok(registeredCommands.has("factoryline.openRequirementEvidence"));
    assert.ok(registeredCommands.has("factoryline.draftTestProof"));
    assert.ok(registeredCommands.has("factoryline.scanCurrentFile"));
    assert.ok(workspaceEvents.get("save"), "scan-on-save must subscribe to document saves");
    assert.ok(context.subscriptions.length >= 18);
    const openEvent = workspaceEvents.get("open");
    const changeEvent = workspaceEvents.get("change");
    const trustEvent = workspaceEvents.get("trust");
    const closeEvent = workspaceEvents.get("close");
    assert.ok(openEvent && changeEvent && trustEvent && closeEvent);
    openEvent(doc);
    await new Promise(resolve => setTimeout(resolve, 180));
    assert.equal(diagnosticEntries.get(docUri.toString())?.length, 1, "opening a test document should produce its missing-draft diagnostic");
    workspaceTrusted = false;
    changeEvent({ document: doc });
    await new Promise(resolve => setTimeout(resolve, 180));
    assert.equal(diagnosticEntries.has(docUri.toString()), false, "untrusted workspaces must clear test-proof diagnostics");
    const draftCommand = registeredCommands.get("factoryline.draftTestProof");
    assert.ok(draftCommand);
    await draftCommand(docUri, 0, "test_lifecycle");
    assert.match(warningMessages.at(-1) || "", /trusted workspace/);
    workspaceTrusted = true;
    trustEvent();
    await new Promise(resolve => setTimeout(resolve, 180));
    assert.equal(diagnosticEntries.get(docUri.toString())?.length, 1, "trust grant should refresh open-document diagnostics");
    closeEvent(doc);
    assert.equal(diagnosticEntries.has(docUri.toString()), false, "closing a document should remove its diagnostics");
    const beforeDeactivate = disposedResources;
    deactivate();
    assert.equal(disposedResources, beforeDeactivate + 1);
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  } finally {
    moduleLoader._load = originalLoad;
    fsPromises.realpath = originalRealpath;
  }
})();

test("single-file scan findings map to editor ranges as the scanner reports them", () => {
  // Measured: `    return yaml.load(open(p))` reports line 4, column 11, end_column 29.
  const report = JSON.stringify({ static_security: { findings: [
    { code: "SECURITY_UNSAFE_YAML", message: "YAML is loaded without an explicit reviewed Loader.", severity: "HIGH", path: "loader.py", line: 4, column: 11, end_line: 4, end_column: 29 },
    { code: "OTHER", message: "elsewhere", severity: "HIGH", path: "other.py", line: 3 },
    { code: "BAD", message: "no line", severity: "LOW", path: "loader.py" },
  ] } });
  const specs = scanDiagnosticSpecs(report, "/work/pkg/loader.py");
  assert.deepEqual(specs, [{ startLine: 3, startColumn: 11, endLine: 3, endColumn: 29,
    message: "YAML is loaded without an explicit reviewed Loader. (single-file scan; cross-file context not applied)", code: "SECURITY_UNSAFE_YAML", level: "warning" }]);
  assert.equal(scanDiagnosticSpecs("not json", "loader.py"), null);
  assert.equal(scanDiagnosticSpecs("{\"partial\": true}", "loader.py"), null);
  assert.deepEqual(scanDiagnosticSpecs(JSON.stringify({ static_security: { findings: [] } }), "loader.py"), []);
  assert.deepEqual(singleFileScanArgs("/tmp/x"), ["scan", "--root", "/tmp/x", "--static-only", "--json"]);
  assert.equal(scanCompleted(null), true);
  assert.equal(scanCompleted({ code: 2 }), true);
  assert.equal(scanCompleted({ code: 2, killed: true, signal: "SIGTERM" }), false);
  assert.equal(scanCompleted({ code: 1 }), false);
  assert.equal(scanCompleted({ code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" }), false);
});
