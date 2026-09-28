"use strict";
const { spawn } = require("node:child_process");
const path = require("node:path");
const { createHash } = require("node:crypto");

const LANES = Object.freeze({
  review: { label: "CF change review", tool: "factory", args: ["change", "review"], limit: "Pattern and guard-path audits require .factory/review-audits.json; review does not execute tests." },
  architecture: { label: "CF architecture health", tool: "factory", args: ["architecture", "health"], limit: "Configured architecture budgets; not runtime or security verification." },
  security: { label: "CF security patterns", tool: "factory", args: ["audit", "security"], limit: "Bounded Python static analysis; not a penetration test or a full multilingual scan." },
  runtime: { label: "CF runtime readiness", tool: "factory", args: ["runtime-audit", "status"], limit: "Reports runtime-audit readiness and existing evidence; does not execute runtime tests." },
  forgeline: { label: "ForgeLine repository inventory", tool: "forge", args: ["qa", "--repo-wide"], limit: "Static repository inventory; not a feature-scoped ForgeLine release gate." },
});

function redact(text) {
  return String(text).replace(/\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{12,})\b/g, "[REDACTED]")
    .replace(/(\b(?:authorization|password|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[=:]\s*)([^\s,;]+)/gi, "$1[REDACTED]");
}

function executable(name) {
  return process.platform === "win32" && ["factory", "forge"].includes(name) ? `${name}.exe` : name;
}

function stopTree(child) {
  if (!child.pid) return;
  if (process.platform === "win32") {
    const killer = spawn("taskkill.exe", ["/pid", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore", shell: false });
    killer.on("error", () => child.kill());
  } else {
    try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
  }
}

function runCommand(command, args, options) {
  const { root } = options;
  if (!path.isAbsolute(root)) return Promise.reject(new Error("An absolute workspace root is required."));
  return new Promise(resolve => _executeCommand(command, args, options, resolve));
}

function _executeCommand(command, args, options, resolve) {
  const { root, signal, timeoutMs = 120000, maxBytes = 8 * 1024 * 1024, onOutput } = options;
    let stdout = "", stderr = "", bytes = 0, stopped, finished = false, fallback;
    const started = Date.now();
    if (signal?.aborted) { resolve(_commandResult("CANCELLED", stdout, stderr, null, 0)); return; }
    const child = spawn(executable(command), args, { cwd: root, shell: false, windowsHide: true, detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"] });
    const finish = (state, exitCode = null) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer); clearTimeout(fallback);
      signal?.removeEventListener("abort", abort);
      resolve(_commandResult(state, stdout, stderr, exitCode, Date.now() - started));
    };
    const stop = (state) => {
      if (finished || stopped) return;
      stopped = state; stopTree(child);
      fallback = setTimeout(() => { child.stdout.destroy(); child.stderr.destroy(); child.unref(); finish(state); }, 3000);
    };
    const abort = () => stop("CANCELLED");
    const timer = setTimeout(() => stop("TIMEOUT"), timeoutMs);
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    const collect = (kind, chunk) => {
      if (stopped || finished) return;
      bytes += Buffer.byteLength(chunk);
      if (bytes > maxBytes) { stop("INCOMPLETE"); return; }
      if (kind === "out") stdout += chunk; else stderr += chunk;
      onOutput?.(redact(chunk));
    };
    child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
    child.stdout.on("data", chunk => collect("out", chunk));
    child.stderr.on("data", chunk => collect("err", chunk));
    child.on("error", error => { stderr = error.message; finish(error.code === "ENOENT" ? "UNAVAILABLE" : "ERROR"); });
    child.on("close", code => finish(stopped || (code === 0 ? "OBSERVED" : "FAILED"), code));
}

function _commandResult(state, stdout, stderr, exitCode, durationMs) {
  return { state, exitCode, stdout, stderr: redact(stderr), durationMs };
}

function parseReport(stdout) {
  const value = JSON.parse(stdout.trim());
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Expected a JSON report object.");
  return value;
}

function auditArgs(lane, root) {
  if (!Object.hasOwn(LANES, lane)) throw new Error("Unknown audit lane.");
  const item = LANES[lane];
  return [...item.args, "--root", root, ...(item.tool === "factory" ? ["--json"] : [])];
}

function describeReport(report) {
  const values = ["state", "verdict", "status", "grade", "passed"].filter(key => report[key] !== undefined)
    .map(key => `${key}=${String(report[key]).slice(0, 60)}`);
  return values.length ? `Reported: ${values.join(", ")}` : "Report collected; inspect findings";
}

async function audit(root, lane, options = {}) {
  const args = auditArgs(lane, root), item = LANES[lane];
  const command = options[item.tool] || item.tool;
  const result = await runCommand(command, args, { ...options, root });
  let report, detail = result.stderr.slice(0, 1000);
  let state = result.state;
  try { report = parseReport(result.stdout); detail = describeReport(report); }
  catch { if (state === "OBSERVED") { state = "INCOMPLETE"; detail = "Command returned no valid JSON object; no result inferred."; } }
  return { lane, label: item.label, state, detail: redact(detail), exitCode: result.exitCode,
    durationMs: result.durationMs, observedAt: new Date().toISOString(), candidateBinding: "UNBOUND",
    limit: item.limit, outputHash: createHash("sha256").update(result.stdout).digest("hex"), report };
}

function summary(results, stale = false) {
  const lines = Object.entries(LANES).map(([key, value]) => {
    const result = results.find(r => r.lane === key);
    return `${value.label}: ${result ? (stale ? "STALE" : result.state) : "NOT_RUN"}${result ? ` — ${result.detail}` : ""}. ${value.limit}`;
  });
  return [...lines, "Candidate binding: UNBOUND. These observations do not approve a release; execute candidate-bound verification separately."].join("\n");
}

function _findingMessage(item) {
  return redact(item.message || item.description || item.kind || item.code || "Inspect report for details").slice(0, 1000);
}

function _findingPath(item) {
  const value = item.path ?? item.facts?.path;
  return typeof value === "string" ? value : undefined;
}

function _findingLine(item) {
  const value = item.line ?? item.facts?.line;
  return Number.isInteger(value) && value > 0 ? value : undefined;
}

function _normalizeFinding(item) {
  return { message: _findingMessage(item), severity: String(item.severity || "information").toLowerCase(), path: _findingPath(item), line: _findingLine(item) };
}

function findings(result) {
  const source = result.report?.findings || result.report?.violations || [];
  if (!Array.isArray(source)) return [];
  return source.slice(0, 200).filter(x => x && typeof x === "object").map(_normalizeFinding);
}

module.exports = { LANES, redact, runCommand, parseReport, auditArgs, audit, summary, findings };
