# Plan: agent-cloud-memory-recall-safety-v1
Spec: specs/agent-cloud-memory-recall-safety-v1.md
Architect verdict: PASS

## Logical decomposition

1. Add optional safety state for migration-safe lifecycle evidence.
2. Classify writes and corrections with one deterministic domain function.
3. Filter exact AgentSpec-derived scope and quarantine before ranking.
4. Render an explainable novice-friendly recall lab.
5. Prove adversarial leakage, mutation resistance, and responsive behavior.

## Tasks

- [x] T1 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts,products/agent-cloud/app/convex/domain.ts,products/agent-cloud/app/convex/seed.ts | verify=`npm run test:convex` | Add migration-safe safety classification.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/memory.ts,products/agent-cloud/app/convex/memory.test.ts | verify=`npm run test:convex` | Implement and prove exact scoped recall and quarantine.
- [x] T3 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/MemoryPanel.tsx,products/agent-cloud/app/src/index.css,products/agent-cloud/app/src/App.test.tsx | verify=`npm test -- --run` | Build the responsive explainable Recall Lab.
- [x] T4 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md | verify=`npm run verify` | Document and proof-gate the recall safety boundary.
