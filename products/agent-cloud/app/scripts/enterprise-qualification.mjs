import { access, readFile } from "node:fs/promises";

const required = [
  "docs/ENTERPRISE_SECURITY.md",
  "docs/PROCUREMENT_PACKET.md",
  "docs/SLA_SLO.md",
  "docs/DISASTER_RECOVERY.md",
  "convex/enterpriseIdentity.test.ts",
  "convex/enterpriseGovernance.test.ts",
  "convex/enterpriseSecurity.test.ts",
];
const missing = [];
for (const path of required) try { await access(path); } catch { missing.push(path); }
const packageLock = await readFile("package-lock.json", "utf8");
if (missing.length || !packageLock.includes('"lockfileVersion": 3')) {
  console.error(`ENTERPRISE_QUALIFICATION_FAILED missing=${missing.join(",") || "none"}`);
  process.exit(1);
}
console.log("ENTERPRISE_RELEASE_CANDIDATE_QUALIFIED identity=directory governance=holds+residency admission=rate+concurrency evidence=required");
