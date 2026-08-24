# Plan: agent-cloud-convex-v1
Spec: specs/agent-cloud-convex-v1.md
Architect verdict: PASS

## Logical decomposition

1. Seal the Convex-only architecture, schema, security boundaries, and visual tokens.
2. Implement and test Convex domain functions for seed, AgentSpec, runs, approvals, memory, receipts, and dashboard queries.
3. Implement the responsive React product shell and realtime views.
4. Exercise the complete UI flow against Convex, audit with Prestige, and produce repository evidence.

## Tasks

- [x] T1 | slice=products/agent-cloud/app | files=products/agent-cloud/app/package.json,products/agent-cloud/app/vite.config.ts,products/agent-cloud/app/tsconfig.json,products/agent-cloud/app/DESIGN.md | verify=`npm run typecheck` | Scaffold React, TypeScript, Convex, and design contracts.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts,products/agent-cloud/app/convex/domain.ts,products/agent-cloud/app/convex/seed.ts,products/agent-cloud/app/convex/dashboard.ts | verify=`npm run test:convex` | Implement schema, policy helpers, idempotent seed, and dashboard query.
- [x] T3 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/control.ts,products/agent-cloud/app/convex/control.test.ts | verify=`npm run test:convex` | Implement and prove AgentSpec, bounded launch, approvals, receipts, and audit writes.
- [x] T4 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/memory.ts,products/agent-cloud/app/convex/memory.test.ts | verify=`npm run test:convex` | Implement and prove scoped memory creation, retrieval, tombstoning, and deletion evidence.
- [x] T5 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/App.tsx,products/agent-cloud/app/src/main.tsx,products/agent-cloud/app/src/index.css,products/agent-cloud/app/src/App.test.tsx | verify=`npm run test` | Implement shell, navigation, overview, and realtime data states.
- [x] T6 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/AgentBuilder.tsx,products/agent-cloud/app/src/components/RunPanel.tsx,products/agent-cloud/app/src/components/MemoryPanel.tsx,products/agent-cloud/app/src/components/EvidencePanel.tsx | verify=`npm run test` | Implement configuration, runs, approvals, memory, evidence, and settings flows.
- [x] T7 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md,products/agent-cloud/app/index.html,products/agent-cloud/app/scripts/verify-stack.mjs | verify=`npm run build` | Add deployment guidance, stack validator, browser verification, and production metadata.
- [x] T8 | slice=products/agent-cloud/app | files=products/agent-cloud/app/package.json | verify=`npm run verify` | Execute Convex tests, UI tests, typecheck, build, and Convex-only validation.
