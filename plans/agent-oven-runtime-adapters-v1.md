# Plan: agent-oven-runtime-adapters-v1
Spec: specs/agent-oven-runtime-adapters-v1.md
Architect verdict: PASS

## Logical decomposition

1. Define the engine registry and worker transport contract without Convex dependencies.
2. Add tenant-scoped adapter configuration and digest pinning to hosted execution.
3. Expose progressive configuration and runtime provenance in the hosted-run UI.
4. Prove reference rejection, digest drift rejection, transport selection, and response validation.

## Tasks

- [ ] T1 | slice=products/agent-cloud/app/runtime | files=products/agent-cloud/app/runtime/runtimeAdapter.ts,products/agent-cloud/app/runtime/runtimeAdapter.test.ts | verify=`npm run test -- --run runtime/runtimeAdapter.test.ts` | implement engine registry, request builder, and transport tests
- [ ] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts,products/agent-cloud/app/convex/runtimeAdapters.ts,products/agent-cloud/app/convex/execution.ts,products/agent-cloud/app/convex/runtimeAdapters.test.ts | verify=`npm run test -- --run convex/runtimeAdapters.test.ts convex/execution.test.ts` | implement schema, public configuration routes, job pinning, and control-plane tests
- [ ] T3 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/HostedRuntimeLauncher.tsx,products/agent-cloud/app/src/components/AgentBuilder.tsx,products/agent-cloud/app/src/App.tsx,products/agent-cloud/app/src/index.css | verify=`npm run typecheck` | add adapter configuration and provenance UI
- [ ] T4 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md,products/agent-cloud/app/package.json | verify=`npm run verify:enterprise` | document the boundary and run release qualification
