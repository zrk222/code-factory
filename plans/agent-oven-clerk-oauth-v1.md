# Plan: agent-oven-clerk-oauth-v1
Spec: specs/agent-oven-clerk-oauth-v1.md
Architect verdict: PASS

- [x] T1 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/HostedAppBoundary.tsx,products/agent-cloud/app/src/AuthBoundary.tsx,products/agent-cloud/app/src/main.tsx | verify=`npx vitest run src/AuthBoundary.test.tsx src/HostedAppBoundary.test.tsx src/PublicLanding.test.tsx` | Replace Auth0 browser providers with Clerk.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/auth.config.ts,products/agent-cloud/app/convex/productionReadinessDomain.ts,products/agent-cloud/app/convex/operations.ts | verify=`npx vitest run convex/productionReadinessDomain.test.ts convex/operations.test.ts` | Replace Convex identity and readiness configuration.
- [x] T3 | slice=products/agent-cloud/app | files=products/agent-cloud/app/docs/CLERK_OAUTH.md,products/agent-cloud/app/scripts/verify-production-env.mjs,products/agent-cloud/app/.env.example | verify=`npm run typecheck` | Add deterministic OAuth-boundary validation and deployment documentation.
- [x] T4 | slice=products/agent-cloud/app | files=products/agent-cloud/app | verify=`npm run verify:enterprise` | Run strict spec, native release, dependency, and production-boundary gates.
