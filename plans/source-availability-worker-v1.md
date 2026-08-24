# Plan: source-availability-worker-v1
Spec: specs/source-availability-worker-v1.md
Architect verdict: PASS

## Logical decomposition

1. Build deterministic bounded worker I/O.
2. Add authenticated, digest-pinned control-plane exchange.
3. Document the external deployment boundary.
4. Prove behavior and release safety.

## Tasks

- [ ] T1 | slice=products/agent-cloud/app/runtime | files=products/agent-cloud/app/runtime/sourceWorker.ts,products/agent-cloud/app/runtime/sourceWorker.test.ts | verify=`npm run test -- --run runtime/sourceWorker.test.ts` | implement bounded HTTPS probes, hashing, retry, and five-source batches
- [ ] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/authoritativeSources.ts,products/agent-cloud/app/convex/authoritativeSources.test.ts,products/agent-cloud/app/convex/routeAuthorization.test.ts | verify=`npm run test -- --run convex/authoritativeSources.test.ts convex/routeAuthorization.test.ts` | implement worker definitions and digest-pinned observations
- [ ] T3 | slice=docs | files=docs/AUTHORITATIVE_SOURCE_CONTROL.md | verify=`rg "deployment required" docs/AUTHORITATIVE_SOURCE_CONTROL.md` | document activation and uptime boundaries
- [ ] T4 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md | verify=`rg "deployment required" products/agent-cloud/app/README.md` | expose worker deployment posture in product documentation
- [ ] T5 | slice=products/agent-cloud/app | files=products/agent-cloud/app/runtime/sourceWorker.test.ts | verify=`npm run verify:enterprise` | prove worker and enterprise release behavior
