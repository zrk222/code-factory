# Plan: agent-cloud-identity-isolation-v1
Spec: specs/agent-cloud-identity-isolation-v1.md
Architect verdict: PASS

- [x] T1 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts,products/agent-cloud/app/convex/access.ts | verify=`npm run test:convex` | Add authenticated membership administration and isolated reads.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/access.test.ts | verify=`npm test` | Prove unauthenticated, cross-workspace, role, revocation, and last-owner denials.
- [x] T3 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/IdentityBoundaryPanel.tsx,products/agent-cloud/app/src/components/OperationsPanel.tsx,products/agent-cloud/app/src/index.css,products/agent-cloud/app/src/App.test.tsx | verify=`npm run verify` | Expose the honest local identity-readiness boundary.
- [x] T4 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md | verify=`npm run verify` | Document deployment requirements and non-goals.
