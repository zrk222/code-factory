# Plan: agent-cloud-budget-enforcement-v1
Spec: specs/agent-cloud-budget-enforcement-v1.md
Architect verdict: PASS

## Logical decomposition

1. Add a run-scoped reservation ledger and budget-control receipt type.
2. Implement atomic reserve, idempotent replay, reconciliation, release, and status.
3. Prove concurrent contention and all fail-closed transitions with Convex tests.
4. Add a plain-language budget console to the existing Runs view.
5. Run mutation, drift, architecture, native, browser, and responsive design gates.

## Tasks

- [x] T1 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts | verify=`npm run test:convex` | Add the reservation ledger and receipt type.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/budget.ts,products/agent-cloud/app/convex/budget.test.ts | verify=`npm run test:convex` | Implement and prove atomic budget transitions.
- [x] T3 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/RunPanel.tsx,products/agent-cloud/app/src/index.css,products/agent-cloud/app/src/App.test.tsx | verify=`npm test -- --run` | Build and test the budget console.
- [x] T4 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md | verify=`npm run verify` | Document the gateway simulation boundary and proof.
