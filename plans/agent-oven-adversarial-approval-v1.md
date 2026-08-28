# Plan: agent-oven-adversarial-approval-v1
Spec: specs/agent-oven-adversarial-approval-v1.md
Architect verdict: PASS

## Tasks

- [x] T1 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/adversarialApprovalDomain.ts,products/agent-cloud/app/convex/adversarialApprovalDomain.test.ts | verify=`npx vitest run convex/adversarialApprovalDomain.test.ts` | Build the deterministic approval and Proof Delta policy.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts,products/agent-cloud/app/convex/control.ts,products/agent-cloud/app/convex/adversarialApprovals.test.ts | verify=`npx vitest run convex/adversarialApprovals.test.ts convex/control.test.ts` | Bind reviews to runs, identities, evidence, expiry, receipts, and transitions.
- [x] T3 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/AgentBuilder.tsx,products/agent-cloud/app/src/components/RunPanel.tsx,products/agent-cloud/app/src/components/RunPanel.test.tsx,products/agent-cloud/app/src/index.css | verify=`npx vitest run src/components/RunPanel.test.tsx && npm run typecheck` | Expose and test safe task modes, adversarial checks, and Proof Delta in the supervision UI.
- [x] T4 | slice=products/agent-cloud/app | files=products/agent-cloud/app | verify=`npm run verify` | Run the complete application, security, architecture, and release gates.
