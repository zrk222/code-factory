# Plan: agent-cloud-operator-lifecycle-v1
Spec: specs/agent-cloud-operator-lifecycle-v1.md
Architect verdict: PASS

## Logical decomposition

1. Extend the append-only data model and canonical lifecycle domain helpers.
2. Implement version, export/import, rollback, emergency control, and BYOK-reference mutations.
3. Expose lifecycle state and provider connections through the realtime dashboard.
4. Add one consolidated operator UI and verify adversarial and responsive behavior.

## Tasks

- [x] T1 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts,products/agent-cloud/app/convex/domain.ts,products/agent-cloud/app/convex/seed.ts | verify=`npm run test:convex` | Add lifecycle schemas, canonical payload validation, and initial version seeding.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/lifecycle.ts,products/agent-cloud/app/convex/lifecycle.test.ts | verify=`npm run test:convex` | Implement and prove append-only versions, import/export, rollback, emergency controls, and secret references.
- [x] T3 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/control.ts,products/agent-cloud/app/convex/dashboard.ts,products/agent-cloud/app/convex/control.test.ts | verify=`npm run test:convex` | Bind lifecycle status to run authorization and expose operator data.
- [x] T4 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/OperationsPanel.tsx,products/agent-cloud/app/src/App.tsx,products/agent-cloud/app/src/index.css,products/agent-cloud/app/src/App.test.tsx | verify=`npm test -- --run` | Add responsive lifecycle, import/export, rollback, emergency-stop, and BYOK-reference controls.
- [x] T5 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md,products/agent-cloud/app/scripts/verify-stack.mjs,products/agent-cloud/app/package.json | verify=`npm run verify` | Document boundaries and run all stack, test, type, build, and security gates.
