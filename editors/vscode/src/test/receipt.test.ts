import * as assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { escapeHtml, receiptHtml, summarizeReceipt } from "../receipt";
import { factoryExecutable, factoryStudioUrl, isFeatureName } from "../runner";
import { meterHtml, savingsHtml } from "../meter";
import { findRequirementEvidence, requirementIds } from "../requirement";
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
    onDidChangeTextDocument: () => disposable,
    onDidChangeWorkspaceFolders: () => disposable,
  },
  window: {
    createOutputChannel: () => outputChannel,
    registerTreeDataProvider: (id: string) => { registeredProviders.push(id); return disposable; },
    showWarningMessage: (message: string) => warningMessages.push(message),
    showTextDocument: async () => { openedDocuments += 1; },
  },
  commands: {
    registerCommand: (name: string, callback: (...args: unknown[]) => unknown) => {
      registeredCommands.set(name, callback);
      return disposable;
    },
  },
  languages: { registerCodeLensProvider: () => disposable },
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
    const context = { subscriptions: [] as unknown[] };
    activate(context);
    assert.ok(registeredProviders.includes("factorylineEvidence"));
    assert.ok(registeredCommands.has("factoryline.assemble"));
    assert.ok(registeredCommands.has("factoryline.openRequirementEvidence"));
    assert.ok(context.subscriptions.length >= 18);
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
