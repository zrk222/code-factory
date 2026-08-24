# Plan: agent-oven-production-readiness-v1
Spec: specs/agent-oven-production-readiness-v1.md (approved)
Architect verdict: PASS

## Logical decomposition (phases)
1. Define a pure, value-redacting readiness classifier.
2. Expose the classifier through an administrator-only Convex query.
3. Render the two-phase go-live cockpit inside Operations.
4. Prove role denial, disclosure absence, responsive UI, and build behavior.

## Tasks (atomic - each independently shippable)
- [x] T1 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/productionReadinessDomain.ts,products/agent-cloud/app/convex/productionReadinessDomain.test.ts | verify=`npx vitest run convex/productionReadinessDomain.test.ts --maxWorkers=2` | Implement and mutation-test the sanitized readiness classifier.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/operations.ts,products/agent-cloud/app/convex/operations.test.ts,products/agent-cloud/app/convex/routeAuthorization.test.ts | verify=`npx vitest run convex/operations.test.ts convex/routeAuthorization.test.ts --maxWorkers=2` | Add the administrator-only server query, register its identity guard, and prove viewer denial.
- [x] T3 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/ProductionActivationPanel.tsx,products/agent-cloud/app/src/components/ProductionActivationPanel.test.tsx,products/agent-cloud/app/src/components/OperationsPanel.tsx | verify=`npx vitest run src/components/ProductionActivationPanel.test.tsx --maxWorkers=2` | Build the novice-friendly two-phase activation cockpit.
- [x] T4 | slice=products/agent-cloud/app | files=products/agent-cloud/app/src/index.css,products/agent-cloud/app/docs/PRODUCTION_RUNBOOK.md,products/agent-cloud/app/docs/RELEASE_CHECKLIST.md | verify=`npm run typecheck && npm run build` | Add responsive polish and align operator documentation with the executable truth.
- [x] T5 | slice=products/agent-cloud/app | files=products/agent-cloud/app/scripts/verify-production-env.mjs,products/agent-cloud/app/package.json | verify=`npm run verify:production-env` | Keep the headless environment gate aligned and fail closed until external references exist.
