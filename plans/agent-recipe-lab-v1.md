# Plan: agent-recipe-lab-v1

Architect verdict: PASS

- [x] T1 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/recipeLabDomain.ts,products/agent-cloud/app/convex/recipeLabDomain.test.ts | verify=`npm test -- recipeLabDomain.test.ts` | Implement bounded candidates, constraint eligibility, Pareto frontier, and deterministic champion selection.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts,products/agent-cloud/app/convex/recipeLab.ts,products/agent-cloud/app/convex/recipeLab.test.ts | verify=`npm test -- recipeLab.test.ts` | Add authorized study, trial, checkpoint, finalization, approval, and redacted query APIs.
- [x] T3 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/_generated/api.d.ts,products/agent-cloud/app/convex/routeAuthorization.test.ts | verify=`npm test -- routeAuthorization.test.ts` | Register the new backend module and enforce public-route authorization coverage.
- [x] T4 | slice=products/agent-cloud/app/src/components | files=products/agent-cloud/app/src/components/AgentRecipeLab.tsx,products/agent-cloud/app/src/components/AgentRecipeLab.test.tsx | verify=`npm test -- AgentRecipeLab.test.tsx` | Add the accessible six-stage Recipe Lab assembly experience.
- [x] T5 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/AgentBuilder.tsx,products/agent-cloud/app/src/index.css | verify=`npm run typecheck` | Mount and responsively style the Recipe Lab inside agent assembly.
- [x] T6 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md,products/agent-cloud/app/docs/AGENT_RECIPE_LAB.md | verify=`npm run verify:enterprise` | Document the hosted-worker boundary and run enterprise, security, drift, and design gates.
