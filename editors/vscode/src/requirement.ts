import { type Dirent } from "node:fs";
import { createHash } from "node:crypto";
import { constants as fsConstants, type BigIntStats } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";

export const requirementPattern = /\b(?:REQ|FR|NFR)-[A-Z0-9][A-Z0-9_-]*\b/g;
const evidenceRoots = [".factory", "receipts", "coverage", "tests", "specs"];
const evidenceExtensions = new Set([".json", ".md", ".yaml", ".yml", ".txt"]);
const excluded = new Set([".git", "node_modules", ".pnpm", "dist", "build", ".gradle", "out"]);

export interface RequirementEvidence {
  file: string;
  line: number;
  preview: string;
}

export interface RequirementProofManifestDraft {
  schema: "factory.e2e_proof_manifest.v1";
  id: string;
  approval: { state: "unapproved"; approved_by: "" };
  working_directory: ".";
  timeout_seconds: number;
  network_egress: "not_granted";
  positive: { argv: string[] };
  negative: { argv: string[] };
  artifact_paths: string[];
}

export interface TestDeclaration {
  line: number;
  name: string;
}
export const MAX_TEST_DECLARATIONS_PER_DOCUMENT = 200;
export const MAX_TEST_PROOF_MANIFEST_BYTES = 64 * 1024;
export const MAX_TEST_PROOF_DOCUMENT_CHARS = 1_000_000;
export const MAX_TEST_PROOF_DOCUMENT_BYTES = 2 * 1024 * 1024;

// Intentionally bounded syntax, not a universal framework/test discovery engine.
export function testDeclarations(text: string, languageId: string): TestDeclaration[] {
  if (text.length > MAX_TEST_PROOF_DOCUMENT_CHARS || Buffer.byteLength(text, "utf8") > MAX_TEST_PROOF_DOCUMENT_BYTES) return [];
  const lines = text.split(/\r?\n/);
  const result: TestDeclaration[] = [];
  for (let line = 0; line < lines.length; line += 1) {
    if (result.length >= MAX_TEST_DECLARATIONS_PER_DOCUMENT) break;
    const value = lines[line];
    let match: RegExpMatchArray | null = null;
    if (languageId === "python") {
      match = value.match(/^\s*(?:async\s+)?def\s+(test_[A-Za-z0-9_]*)\s*\(/);
      if (match) result.push({ line, name: match[1] });
      continue;
    }
    if (["javascript", "javascriptreact", "typescript", "typescriptreact"].includes(languageId)) {
      match = value.match(/\b(?:test|it)\s*\(\s*(['"])([^'"\n]+)\1\s*,/);
      if (match) result.push({ line, name: match[2] });
    }
  }
  return result;
}

export function testProofId(relativeFile: string, testName: string, line?: number): string {
  const slug = testName.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[^A-Za-z0-9]+/, "").slice(0, 40) || "test";
  const linePart = line === undefined ? "line-0" : `line-${Math.max(0, Math.trunc(line)) + 1}`;
  const digest = createHash("sha256").update(`${relativeFile.replace(/\\/g, "/")}\0${testName}\0${line ?? ""}`).digest("hex").slice(0, 16);
  return `test-${slug}-${linePart}-${digest}`.slice(0, 96);
}

export function isRequirementId(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(value);
}

export function requirementProofManifestPath(workspace: string, requirementId: string): string {
  if (!isRequirementId(requirementId)) throw new Error("Invalid requirement identifier.");
  return path.join(workspace, ".factory", "requirement-proofs", requirementId, "e2e-manifest.json");
}

function checkProofRead(signal?: AbortSignal): void {
  if (signal?.aborted) throw new Error("Proof manifest read was cancelled.");
}

async function proofRead<T>(signal: AbortSignal | undefined, operation: () => Promise<T>): Promise<T> {
  checkProofRead(signal);
  const result = await operation();
  checkProofRead(signal);
  return result;
}

function validateProofId(requirementId: string): void {
  if (!isRequirementId(requirementId) || requirementId.length > 96) throw new Error("Invalid proof identifier.");
}

async function resolveProofDirectory(root: string, signal?: AbortSignal): Promise<string> {
  let current = root;
  for (const component of [".factory", "requirement-proofs"]) {
    current = await verifyProofDirectory(root, path.join(current, component), signal);
  }
  return current;
}

async function verifyProofDirectory(root: string, candidate: string, signal?: AbortSignal): Promise<string> {
  const stat = await proofRead(signal, () => fs.lstat(candidate, { bigint: true }));
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error("Proof path contains a linked or non-directory component.");
  const real = await proofRead(signal, () => fs.realpath(candidate));
  const relative = path.relative(root, real);
  if (relative.startsWith(`..${path.sep}`) || relative === ".." || path.isAbsolute(relative)) throw new Error("Proof path escaped the workspace.");
  return candidate;
}

async function verifyProofManifestPath(manifest: string, signal?: AbortSignal) {
  const stat = await proofRead(signal, () => fs.lstat(manifest, { bigint: true }));
  const bounded = stat.size <= BigInt(MAX_TEST_PROOF_MANIFEST_BYTES);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink > 1n || !bounded) {
    throw new Error("Proof manifest must be a bounded regular single-link file.");
  }
  return stat;
}

function validateOpenedManifest(opened: BigIntStats, pathStat: BigIntStats): void {
  const bounded = opened.size <= BigInt(MAX_TEST_PROOF_MANIFEST_BYTES);
  const same = opened.dev === pathStat.dev && opened.ino === pathStat.ino;
  if (!opened.isFile() || opened.nlink > 1n || !bounded || !same) throw new Error("Proof manifest changed identity or exceeded its size bound.");
}

async function readProofBytes(handle: Awaited<ReturnType<typeof fs.open>>, signal?: AbortSignal): Promise<{ buffer: Buffer; length: number }> {
  const buffer = Buffer.alloc(MAX_TEST_PROOF_MANIFEST_BYTES + 1);
  let length = 0;
  while (length < buffer.length) {
    const result = await proofRead(signal, () => handle.read(buffer, length, buffer.length - length, length));
    if (!result.bytesRead) break;
    length += result.bytesRead;
  }
  return { buffer, length };
}

function manifestIdentityUnchanged(before: BigIntStats, after: BigIntStats, pathStat: BigIntStats, length: number): boolean {
  const stableFields = ["dev", "ino", "size", "nlink", "mtimeNs", "ctimeNs"] as const;
  const stable = stableFields.every((field) => before[field] === after[field]);
  const samePath = !pathStat.isSymbolicLink() && pathStat.dev === after.dev && pathStat.ino === after.ino;
  return length <= MAX_TEST_PROOF_MANIFEST_BYTES && after.size <= BigInt(MAX_TEST_PROOF_MANIFEST_BYTES) && stable && samePath;
}

function parseProofManifest(buffer: Buffer, length: number): Record<string, unknown> {
  const parsed: unknown = JSON.parse(buffer.toString("utf8", 0, length));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Proof manifest must contain a JSON object.");
  return parsed as Record<string, unknown>;
}

export async function readTestProofManifest(workspace: string, requirementId: string, signal?: AbortSignal): Promise<Record<string, unknown>> {
  validateProofId(requirementId);
  const root = await proofRead(signal, () => fs.realpath(workspace));
  const directory = await resolveProofDirectory(root, signal);
  const requirementDirectory = await verifyProofDirectory(root, path.join(directory, requirementId), signal);
  const manifest = path.join(requirementDirectory, "e2e-manifest.json");
  const pathStat = await verifyProofManifestPath(manifest, signal);
  checkProofRead(signal);
  const handle = await fs.open(manifest, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  try {
    const before = await proofRead(signal, () => handle.stat({ bigint: true }));
    validateOpenedManifest(before, pathStat);
    const { buffer, length } = await readProofBytes(handle, signal);
    const after = await proofRead(signal, () => handle.stat({ bigint: true }));
    const afterPath = await proofRead(signal, () => fs.lstat(manifest, { bigint: true }));
    if (!manifestIdentityUnchanged(before, after, afterPath, length)) throw new Error("Proof manifest changed during bounded read.");
    return parseProofManifest(buffer, length);
  } finally {
    await handle.close();
  }
}

function assertProofPathInside(root: string, target: string, message: string): void {
  const relative = path.relative(root, target);
  if (!relative || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw new Error(message);
}

async function createProofDirectoryComponent(current: string): Promise<void> {
  try {
    await fs.mkdir(current);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
}

async function verifyCreatedProofDirectory(root: string, current: string): Promise<void> {
  const stat = await fs.lstat(current);
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error("Requirement proof path contains a linked or non-directory component.");
  const real = await fs.realpath(current);
  assertProofPathInside(root, real, "Requirement proof path escaped the workspace.");
}

async function ensureProofDirectory(workspace: string, requirementId: string, ...children: string[]): Promise<string> {
  validateProofId(requirementId);
  const root = await fs.realpath(workspace);
  const base = path.join(root, ".factory", "requirement-proofs", requirementId, ...children);
  assertProofPathInside(root, base, "Requirement proof path escaped the workspace.");
  let current = root;
  for (const part of path.relative(root, base).split(path.sep)) {
    current = path.join(current, part);
    await createProofDirectoryComponent(current);
    await verifyCreatedProofDirectory(root, current);
  }
  return current;
}

export async function createUnapprovedRequirementProofDraft(
  workspace: string,
  requirementId: string,
  relativeTestFile?: string,
): Promise<string> {
  const root = await fs.realpath(workspace);
  if (relativeTestFile) {
    const normalized = relativeTestFile.replace(/\\/g, "/");
    if (path.isAbsolute(relativeTestFile) || normalized.split("/").some(part => part === "..")) {
      throw new Error("Test source path must stay inside the workspace.");
    }
    const source = await fs.realpath(path.join(root, relativeTestFile));
    const escaped = path.relative(root, source);
    if (escaped.startsWith(`..${path.sep}`) || path.isAbsolute(escaped) || !(await fs.stat(source)).isFile()) {
      throw new Error("Test source path must identify a file inside the workspace.");
    }
  }
  const directory = await ensureProofDirectory(root, requirementId);
  const manifest = requirementProofManifestPath(workspace, requirementId);
  const draft: RequirementProofManifestDraft = {
    schema: "factory.e2e_proof_manifest.v1",
    id: requirementId,
    approval: { state: "unapproved", approved_by: "" },
    working_directory: ".",
    timeout_seconds: 120,
    network_egress: "not_granted",
    positive: { argv: [] },
    negative: { argv: [] },
    artifact_paths: relativeTestFile ? [relativeTestFile.replace(/\\/g, "/")] : [],
  };
  // Exclusive creation prevents replacing a reviewed or previously edited manifest.
  const handle = await fs.open(manifest, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(draft, null, 2)}\n`, "utf8");
  } catch (error) {
    await handle.close();
    await fs.unlink(manifest).catch(() => undefined);
    throw error;
  }
  await handle.close();
  return manifest;
}

export function requirementIds(text: string): string[] {
  return [...new Set(text.match(requirementPattern) ?? [])];
}

async function evidenceFiles(root: string, depth = 6): Promise<string[]> {
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
      return excluded.has(entry.name) ? [] : evidenceFiles(target, depth - 1);
    }
    return entry.isFile() && evidenceExtensions.has(path.extname(entry.name).toLowerCase()) ? [target] : [];
  }));
  return nested.flat();
}

export async function findRequirementEvidence(workspace: string, requirementId: string): Promise<RequirementEvidence[]> {
  const files = (await Promise.all(evidenceRoots.map((root) => evidenceFiles(path.join(workspace, root))))).flat();
  const matches: RequirementEvidence[] = [];
  for (const file of files.slice(0, 2_000)) {
    let stat;
    try {
      stat = await fs.stat(file);
    } catch {
      continue;
    }
    if (stat.size > 2_000_000) {
      continue;
    }
    let content: string;
    try {
      content = await fs.readFile(file, "utf8");
    } catch {
      continue;
    }
    const lines = content.split(/\r?\n/);
    const index = lines.findIndex((line) => line.includes(requirementId));
    if (index >= 0) {
      matches.push({ file, line: index, preview: lines[index].trim().slice(0, 180) });
    }
  }
  return matches.sort((left, right) => left.file.localeCompare(right.file));
}
