import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const allowedExtensions = new Set([".ts", ".tsx", ".js", ".mjs", ".json", ".md"]);
const ignored = new Set(["node_modules", "dist", ".convex", "_generated"]);
const forbidden = ["@" + "supabase", "SUPA" + "BASE_URL", "supabase" + ".co"];
const files = [];

async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (ignored.has(entry.name)) continue;
    const fullPath = join(directory, entry.name);
    if (entry.isDirectory()) await walk(fullPath);
    else if (allowedExtensions.has(extname(entry.name))) files.push(fullPath);
  }
}

await walk(root);
const violations = [];
for (const file of files) {
  const content = await readFile(file, "utf8");
  for (const needle of forbidden) {
    if (content.toLowerCase().includes(needle.toLowerCase())) {
      violations.push(`${relative(root, file)} contains forbidden stack marker`);
    }
  }
}

if (violations.length) {
  console.error(violations.join("\n"));
  process.exit(1);
}

console.log(`CONVEX_ONLY_STACK verified across ${files.length} source and manifest files.`);
