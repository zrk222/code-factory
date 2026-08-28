# Plan: agent-cloud-memory-governance-v1
Spec: specs/agent-cloud-memory-governance-v1.md
Architect verdict: PASS

## Logical decomposition

1. Extend the memory lifecycle schema and canonical export contract.
2. Implement correction, content erasure, retention, and export with append-only evidence.
3. Expose active and historical memory through the realtime dashboard.
4. Upgrade the memory operator surface and prove adversarial and responsive behavior.

## Tasks

- [x] T1 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts,products/agent-cloud/app/convex/domain.ts,products/agent-cloud/app/convex/seed.ts | verify=`npm run test:convex` | Add lifecycle fields, receipt types, canonical export, and idempotent policy backfill.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/memory.ts,products/agent-cloud/app/convex/memory.test.ts | verify=`npm run test:convex` | Implement and prove correction, erasure, export, retention, and authority separation.
- [x] T3 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/dashboard.ts | verify=`npm run test:convex` | Expose active memory, complete provenance ledger, and canonical export.
- [x] T4 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/MemoryPanel.tsx,products/agent-cloud/app/src/App.tsx,products/agent-cloud/app/src/index.css,products/agent-cloud/app/src/App.test.tsx | verify=`npm test -- --run` | Build responsive correction, erasure, export, retention, and provenance controls.
- [x] T5 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md,products/agent-cloud/app/DESIGN.md | verify=`npm run verify` | Document boundaries and run stack, test, type, build, security, architecture, mutation, and render gates.
