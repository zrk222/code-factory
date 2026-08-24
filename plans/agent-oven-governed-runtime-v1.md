# Plan: agent-oven-governed-runtime-v1
Spec: specs/agent-oven-governed-runtime-v1.md
Architect verdict: PASS

## Logical decomposition

1. Add governed preset, evidence, snapshot, compliance, and remote database schemas.
2. Implement authenticated policy/database APIs and internal worker evidence APIs.
3. Expose novice-safe runtime and database ingredients in the assembler.
4. Prove authorization, redaction, version pinning, resume integrity, compliance, and database write approval.

## Tasks

- [x] T1 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts,products/agent-cloud/app/convex/agentIntelligence.ts,products/agent-cloud/app/convex/agentIntelligenceDomain.ts | verify=`npm run test -- --run convex/agentIntelligence.test.ts` | Implement governed runtime evidence and compliance.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/databaseTools.ts,products/agent-cloud/app/convex/databaseTools.test.ts | verify=`npm run test -- --run convex/databaseTools.test.ts` | Implement remote database connection and operation contracts.
- [x] T3 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/GovernedRuntimePanel.tsx,products/agent-cloud/app/src/components/DatabaseToolPanel.tsx,products/agent-cloud/app/src/components/WorkflowAssembler.tsx | verify=`npm run test -- --run src/components/GovernedRuntimePanel.test.tsx` | Add novice-first governed runtime and database assembly UI.
- [x] T4 | slice=products/agent-cloud/app | files=products/agent-cloud/app/docs/AGENT_INFRA_PATTERN_MATRIX.md,products/agent-cloud/app/convex/routeAuthorization.test.ts | verify=`npm run verify:enterprise` | Document provenance and run the full qualification gate.
