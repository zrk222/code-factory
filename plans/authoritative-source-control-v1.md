# Plan: authoritative-source-control-v1
Spec: specs/authoritative-source-control-v1.md
Architect verdict: PASS

## Logical decomposition

1. Implement deterministic source and redundancy-group evaluation.
2. Add tenant-scoped source definitions and idempotent trusted-worker observations.
3. Gate execution before reservation when required source groups are not ready.
4. Expose source assurance and honest availability states in the Knowledge Wall.

## Tasks

- [ ] T1 | slice=products/agent-cloud/app/runtime | files=products/agent-cloud/app/runtime/sourceAssurance.ts,products/agent-cloud/app/runtime/sourceAssurance.test.ts | verify=`npm run test -- --run runtime/sourceAssurance.test.ts` | implement source state and redundancy evaluation
- [ ] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts,products/agent-cloud/app/convex/authoritativeSources.ts,products/agent-cloud/app/convex/authoritativeSources.test.ts,products/agent-cloud/app/convex/routeAuthorization.test.ts | verify=`npm run test -- --run convex/authoritativeSources.test.ts convex/routeAuthorization.test.ts` | implement source definitions, observations, readiness, and authorization
- [ ] T3 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/execution.ts,products/agent-cloud/app/convex/execution.test.ts | verify=`npm run test -- --run convex/execution.test.ts convex/authoritativeSources.test.ts` | gate execution before reservation and job creation
- [ ] T4 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/SourceAssurancePanel.tsx,products/agent-cloud/app/src/components/SourceAssurancePanel.test.tsx,products/agent-cloud/app/src/components/KnowledgeWall.tsx,products/agent-cloud/app/src/index.css | verify=`npm run test -- --run src/components/SourceAssurancePanel.test.tsx` | add novice source-assurance configuration and readiness UI
