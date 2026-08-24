import { access, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

const requiredFiles = [
  "dist/index.html",
  "public/.well-known/security.txt",
  "public/legal/privacy.html",
  "public/legal/terms.html",
  "docs/PRODUCTION_RUNBOOK.md",
  "docs/RELEASE_CHECKLIST.md",
  "docs/INCIDENT_RUNBOOK.md",
  "docs/OUTCOME_AGENT_EXCHANGE.md",
  "docs/PORTABLE_AGENT_COMPOSER.md",
  "docs/ADVERSARIAL_APPROVAL.md",
  "public/.well-known/agent-card.json",
  "public/.well-known/outcome-agent-contract.json",
  "public/.well-known/runtime-compatibility.json",
  "vercel.json",
];

const missing = [];
for (const path of requiredFiles) {
  try { await access(path); } catch { missing.push(path); }
}
if (missing.length) {
  console.error(`RELEASE_QUALIFICATION_FAILED missing=${missing.join(",")}`);
  process.exit(1);
}

const manifest = JSON.parse(await readFile("vercel.json", "utf8"));
const headerNames = new Set((manifest.headers?.[0]?.headers ?? []).map((header) => header.key.toLowerCase()));
const requiredHeaders = ["content-security-policy", "referrer-policy", "x-content-type-options", "permissions-policy"];
const absentHeaders = requiredHeaders.filter((header) => !headerNames.has(header));
if (absentHeaders.length) {
  console.error(`RELEASE_QUALIFICATION_FAILED missing_headers=${absentHeaders.join(",")}`);
  process.exit(1);
}

const jsAssets = await stat("dist/assets");
if (!jsAssets.isDirectory()) {
  console.error("RELEASE_QUALIFICATION_FAILED dist/assets is not a directory");
  process.exit(1);
}

console.log(`RELEASE_QUALIFIED files=${requiredFiles.length} security_headers=${requiredHeaders.length} stack=convex-only`);
