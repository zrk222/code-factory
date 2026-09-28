"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { LANES, audit, auditArgs, parseReport, runCommand, summary, findings } = require("../index.cjs");

const root = process.cwd();

test("each lane executes a fixed command with an explicit root", () => {
  assert.deepEqual(auditArgs("review", root), ["change", "review", "--root", root, "--json"]);
  assert.deepEqual(auditArgs("forgeline", root), ["qa", "--repo-wide", "--root", root]);
  assert.throws(() => auditArgs("arbitrary", root), /Unknown audit lane/);
  assert.deepEqual(Object.keys(LANES), ["review", "architecture", "security", "runtime", "forgeline"]);
});

test("process failures, cancellation and output limits stay closed", async () => {
  const failed = await runCommand(process.execPath, ["-e", "process.stdout.write(JSON.stringify({state:'BLOCKED'})); process.exit(3)"], { root });
  assert.equal(failed.state, "FAILED");
  assert.equal(parseReport(failed.stdout).state, "BLOCKED");
  const incomplete = await runCommand(process.execPath, ["-e", "process.stdout.write('x'.repeat(10000))"], { root, maxBytes: 100 });
  assert.equal(incomplete.state, "INCOMPLETE");
  const controller = new AbortController();
  const pending = runCommand(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { root, signal: controller.signal });
  controller.abort();
  assert.equal((await pending).state, "CANCELLED");
  const timeout = await runCommand(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { root, timeoutMs: 50 });
  assert.equal(timeout.state, "TIMEOUT");
});

test("missing executable and malformed reports never become passes", async () => {
  const missing = await audit(root, "security", { factory: path.join(root, "missing-factory-executable") });
  assert.equal(missing.state, "UNAVAILABLE");
  assert.equal(missing.candidateBinding, "UNBOUND");
  const malformed = await audit(root, "security", { factory: process.execPath });
  assert.notEqual(malformed.state, "OBSERVED");
  assert.match(summary([missing]), /ForgeLine repository inventory: NOT_RUN/);
  assert.match(summary([missing], true), /CF security patterns: STALE/);
});

test("findings are bounded and redact sensitive literals", () => {
  const found = findings({ report: { findings: [{ message: "api_key=secret-value", severity: "high", path: "src/a.py", line: 4 }] } });
  assert.equal(found.length, 1);
  assert.equal(found[0].message, "api_key=[REDACTED]");
});
