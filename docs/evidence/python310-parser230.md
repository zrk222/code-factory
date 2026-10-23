# Python3.10 fixture parser repair

- Ubuntu and macOS Python3.10 CI failed the same four Django fixture checks.
- Cause: the fixture index directly imported `tomllib`, absent on3.10, then
  returned no proof. It now reuses CF's existing `tomli` compatibility fallback.
- Only those four failed cases were run locally: **4 passed in1.59s** under
  CPython3.11 with source-module `tomllib` imports blocked. This is a fallback
  simulation; native3.10 CI verification remains pending.
- Independent ECC source review passes: one import substitution, no authority
  predicate, expected-result, dependency, module-count or severity change.
- The initial overbroad simulation blocked pytest bootstrap; its error remains
  preserved. It is not a product test failure or a passing observation.
- The active plan now lists remaining work and links completed regression evidence.
- Native candidate quality remains failed. Fresh actionable precision remains
  **0/49 decided,8 unclear**, Wilson95%0–7.27%; no precision gain or merge claim.
