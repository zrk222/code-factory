# Plan: booked-job-concierge-v1
Spec: specs/booked-job-concierge-v1.md
Architect verdict: PASS

## Logical decomposition

1. Define the isolated concierge schema and server-owned decision rules.
2. Implement authenticated profile, adapter, intake, approval, booking, outcome, and dashboard APIs.
3. Build a novice four-step experience and business-value dashboard.
4. Prove consent denial, raw-secret denial, production fail-closed behavior, approval replay rejection, outcome classification, and UI completion.

## Tasks

- [ ] T1 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts,products/agent-cloud/app/convex/conciergeDomain.ts,products/agent-cloud/app/convex/concierge.ts,products/agent-cloud/app/convex/concierge.test.ts | verify=`npm run test -- --run convex/concierge.test.ts` | Add concierge schema, domain logic, APIs, and backend tests.
- [ ] T2 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/BookedJobConcierge.tsx,products/agent-cloud/app/src/components/BookedJobConcierge.test.tsx,products/agent-cloud/app/src/components/AgentBuilder.tsx,products/agent-cloud/app/src/index.css | verify=`npm run test -- --run src/components/BookedJobConcierge.test.tsx` | Add the novice wizard, sample lead path, outcome dashboard, and component tests.
- [ ] T3 | slice=products/agent-cloud/app | files=products/agent-cloud/app/convex/dashboard.ts,products/agent-cloud/app/convex/_generated/api.d.ts,products/agent-cloud/app/src/App.tsx,products/agent-cloud/app/src/App.test.tsx | verify=`npm run verify:enterprise` | Bind dashboard data, API typing, and full release verification.
- [ ] T4 | slice=specs | files=specs/booked-job-concierge-v1.md,specs/booked-job-concierge-v1.ssat.yaml | verify=`specline audit booked-job-concierge-v1 --root . --files products/agent-cloud/app/convex/concierge.ts products/agent-cloud/app/src/components/BookedJobConcierge.tsx --slice booked-job-concierge-v1` | Audit drift and generate the durable handoff.
