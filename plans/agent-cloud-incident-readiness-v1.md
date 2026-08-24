# Plan: agent-cloud-incident-readiness-v1
Spec: specs/agent-cloud-incident-readiness-v1.md
Architect verdict: PASS

## Logical decomposition

1. Add incident and recovery-check state with receipt types.
2. Implement transactional containment and fail-closed recovery.
3. Expose incident history through the dashboard and safety UI.
4. Prove hostile transitions, responsive rendering, and the Convex boundary.

## Tasks

- [x] T1 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts | verify=`npm run test:convex` | Add incident and recovery schemas.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/incidents.ts,products/agent-cloud/app/convex/incidents.test.ts | verify=`npm run test:convex` | Implement and prove containment and recovery.
- [x] T3 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/dashboard.ts | verify=`npm run test:convex` | Expose incident history.
- [x] T4 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/IncidentResponsePanel.tsx,products/agent-cloud/app/src/components/ReleaseSafetyPanel.tsx,products/agent-cloud/app/src/App.tsx,products/agent-cloud/app/src/index.css | verify=`npm test -- --run` | Build the responsive runbook surface.
- [x] T5 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md | verify=`npm run verify` | Document and proof-gate the local incident boundary.
