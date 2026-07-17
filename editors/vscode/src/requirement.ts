import { type Dirent } from "node:fs";
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
