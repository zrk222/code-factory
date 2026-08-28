# Plan: agent-cloud-trust-capabilities-v1
Spec: specs/agent-cloud-trust-capabilities-v1.md
Architect verdict: PASS

1. Add run-bound capability and explainable decision records.
2. Enforce approval, scope, expiry, replay, revocation, and cost in Convex mutations.
3. Prove fail-closed paths and zero-write denials with Convex tests.
4. Add the supervised Trust Gateway console to Runs.
5. Run native, architecture, mutation, security, and responsive visual gates.

- [x] T1 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts,products/agent-cloud/app/convex/trust.ts | verify=`npm run test:convex` | Add the capability and decision data model plus fail-closed gateway.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/trust.test.ts | verify=`npm test` | Prove exact authorization and denial paths.
- [x] T3 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/TrustGatewayPanel.tsx,products/agent-cloud/app/src/components/RunPanel.tsx,products/agent-cloud/app/src/index.css,products/agent-cloud/app/src/App.test.tsx | verify=`npm run verify` | Build and verify the responsive operator console.
- [x] T4 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md | verify=`npm run verify` | Document the supervised local capability boundary.
