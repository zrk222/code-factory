# Plan: agent-oven-public-launch-v1
Spec: specs/agent-oven-public-launch-v1.md (approved)
Architect verdict: PASS

## Logical decomposition (phases)
1. Separate the public and protected route boundaries before any provider initialization.
2. Build the public product-led landing page and customer-safe closed state.
3. Preserve the hosted Convex tenant model and activate the cloud deployment configuration.
4. Prove route, accessibility, tenant isolation, build, and production HTTP behavior.

## Tasks (atomic - each independently shippable)
- [x] T1 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/PublicLanding.tsx,products/agent-cloud/app/src/PublicLanding.test.tsx | verify=`npm test -- PublicLanding.test.tsx` | Add a public landing component and behavior tests.
- [x] T2 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/main.tsx,products/agent-cloud/app/src/HostedAppBoundary.tsx | verify=`npm run typecheck` | Route `/` publicly and keep `/app` fail-closed until valid browser configuration exists.
- [x] T3 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/index.css | verify=`npm run build` | Add responsive landing, access-state, and focus styles using the committed visual contract.
- [x] T4 | slice=products/agent-cloud/app | files=products/agent-cloud/app/netlify.toml,products/agent-cloud/app/scripts/verify-stack.mjs | verify=`npm run verify:stack` | Harden hosting redirects and security headers without exposing secrets.
- [x] T5 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/access.ts,products/agent-cloud/app/convex/access.test.ts | verify=`npm run test:convex -- access.test.ts` | Re-run cross-tenant access and owner-bootstrap tests against the unchanged server boundary.
- [x] T6 | slice=products/agent-cloud/app | files=products/agent-cloud/app/package.json | verify=`npx vitest run --maxWorkers=4 && npm run typecheck && npm run build` | Run the full application qualification suite and produce the production bundle.
- [x] T7 | slice=products/agent-cloud/app | files=products/agent-cloud/app/netlify.toml | verify=`curl --fail https://agent-oven.netlify.app/` | Promote the qualified bundle and verify `/` plus `/app` return HTTP 200.
- [x] T8 | slice=products/agent-cloud/app | files=products/agent-cloud/app/public/agent-oven-mark.svg,products/agent-cloud/app/index.html | verify=`curl --fail https://agent-oven.netlify.app/agent-oven-mark.svg` | Publish the Agent Oven identity mark and apply customer-facing Auth0 branding.
