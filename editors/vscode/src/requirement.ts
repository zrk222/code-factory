import { type Dirent } from "node:fs";
import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
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

export async function readTestProofManifest(workspace: string, requirementId: string, signal?: AbortSignal): Promise<Record<string, unknown>> {
  const check = (): void => { if (signal?.aborted) throw new Error("Proof manifest read was cancelled."); };
  const wait = async <T>(operation: Promise<T>): Promise<T> => { check(); const result = await operation; check(); return result; };
  if (!isRequirementId(requirementId) || requirementId.length > 96) throw new Error("Invalid proof identifier.");
  const root = await wait(fs.realpath(workspace));
  const components = [".factory", "requirement-proofs", requirementId];
  let current = root;
  for (const component of components) {
    current = path.join(current, component);
    const stat = await wait(fs.lstat(current, { bigint: true }));
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error("Proof path contains a linked or non-directory component.");
    const real = await wait(fs.realpath(current));
    const relative = path.relative(root, real);
    if (relative.startsWith(`..${path.sep}`) || relative === ".." || path.isAbsolute(relative)) throw new Error("Proof path escaped the workspace.");
  }
  const manifest = path.join(current, "e2e-manifest.json");
  const beforePath = await wait(fs.lstat(manifest, { bigint: true }));
  if (beforePath.isSymbolicLink() || !beforePath.isFile() || beforePath.nlink > 1n || beforePath.size > BigInt(MAX_TEST_PROOF_MANIFEST_BYTES)) {
    throw new Error("Proof manifest must be a bounded regular single-link file.");
  }
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  check();
  const handle = await fs.open(manifest, fsConstants.O_RDONLY | noFollow);
  try {
    check();
    const before = await wait(handle.stat({ bigint: true }));
    if (!before.isFile() || before.nlink > 1n || before.size > BigInt(MAX_TEST_PROOF_MANIFEST_BYTES) || before.dev !== beforePath.dev || before.ino !== beforePath.ino) {
      throw new Error("Proof manifest changed identity or exceeded its size bound.");
    }
    const buffer = Buffer.alloc(MAX_TEST_PROOF_MANIFEST_BYTES + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await wait(handle.read(buffer, offset, buffer.length - offset, offset));
      if (!bytesRead) break;
      offset += bytesRead;
    }
    const after = await wait(handle.stat({ bigint: true }));
    const afterPath = await wait(fs.lstat(manifest, { bigint: true }));
    if (offset > MAX_TEST_PROOF_MANIFEST_BYTES || after.size > BigInt(MAX_TEST_PROOF_MANIFEST_BYTES) ||
        before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.nlink !== after.nlink || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
        afterPath.isSymbolicLink() || afterPath.dev !== after.dev || afterPath.ino !== after.ino) {
      throw new Error("Proof manifest changed during bounded read.");
    }
    const parsed: unknown = JSON.parse(buffer.toString("utf8", 0, offset));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Proof manifest must contain a JSON object.");
    return parsed as Record<string, unknown>;
  } finally {
    await handle.close();
  }
}

async function ensureProofDirectory(workspace: string, requirementId: string, ...children: string[]): Promise<string> {
  if (!isRequirementId(requirementId) || requirementId.length > 96) throw new Error("Invalid proof identifier.");
  const root = await fs.realpath(workspace);
  const base = path.join(root, ".factory", "requirement-proofs", requirementId, ...children);
  const relative = path.relative(root, base);
  if (!relative || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("Requirement proof path escaped the workspace.");
  }
  let current = root;
  for (const part of relative.split(path.sep)) {
    current = path.join(current, part);
    try {
      await fs.mkdir(current);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    const stat = await fs.lstat(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error("Requirement proof path contains a linked or non-directory component.");
    }
    const real = await fs.realpath(current);
    const escaped = path.relative(root, real);
    if (escaped.startsWith(`..${path.sep}`) || path.isAbsolute(escaped)) {
      throw new Error("Requirement proof path escaped the workspace.");
    }
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
