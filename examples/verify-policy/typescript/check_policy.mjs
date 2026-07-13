import { readFileSync } from "node:fs";

const policy = JSON.parse(readFileSync(process.argv[2], "utf8"));
const checks = {
  "release.require_ci": policy.release?.require_ci === true,
  "quality.require_hollow_tests": policy.quality?.require_hollow_tests === true,
};
const failed = Object.entries(checks)
  .filter(([, passed]) => !passed)
  .map(([name]) => name);

if (failed.length) {
  console.log(`policy rejected: ${failed.join(", ")}`);
  process.exit(1);
}

console.log("policy accepted");
