# Plan: agent-cloud-release-safety-v1
Spec: specs/agent-cloud-release-safety-v1.md
Architect verdict: PASS

## Logical decomposition

1. Add the canary lifecycle schema and evidence contract.
2. Implement fail-closed start, observation, promotion, and rollback operations.
3. Expose release history through the dashboard and operator UI.
4. Prove transition failures, responsive rendering, and Convex-only boundaries.

## Tasks

- [x] T1 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts | verify=`npm run test:convex` | Add bounded release-candidate state.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/releases.ts,products/agent-cloud/app/convex/releases.test.ts | verify=`npm run test:convex` | Implement and prove canary lifecycle.
- [x] T3 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/dashboard.ts | verify=`npm run test:convex` | Expose release history.
- [x] T4 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/ReleaseSafetyPanel.tsx,products/agent-cloud/app/src/App.tsx,products/agent-cloud/app/src/index.css,products/agent-cloud/app/src/App.test.tsx | verify=`npm test -- --run` | Build responsive release controls.
- [x] T5 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md | verify=`npm run verify` | Document and proof-gate the security-alpha boundary.
