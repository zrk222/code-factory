# Plan: agent-oven-portable-composer-v1
Spec: specs/agent-oven-portable-composer-v1.md
Architect verdict: PASS

## Logical decomposition

1. Compile plain-language intent into deterministic runtime, authority, graph, and evidence controls.
2. Persist only digest-bound controls and append a compilation receipt.
3. Save runtime and inference choices in immutable blueprint versions and fail closed on an unvalidated external adapter.
4. Provide an accessible form-agent hybrid with visible questions, gates, and proof.
5. Publish compatibility documentation and run native, architecture, release, and browser gates.

## Tasks

- [x] T1 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/agentComposerDomain.ts,products/agent-cloud/app/convex/agentComposerDomain.test.ts | verify=`npx vitest run convex/agentComposerDomain.test.ts` | Build and prove the deterministic intent compiler.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/agentComposer.ts,products/agent-cloud/app/convex/agentComposer.test.ts,products/agent-cloud/app/convex/schema.ts | verify=`npx vitest run convex/agentComposer.test.ts` | Store digest-bound drafts without raw descriptions.
- [x] T3 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/blueprints.ts,products/agent-cloud/app/convex/blueprints.test.ts | verify=`npx vitest run convex/blueprints.test.ts` | Preserve runtime and inference choices and block unvalidated external adapters.
- [x] T4 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/IntentComposer.tsx,products/agent-cloud/app/src/components/IntentComposer.test.tsx,products/agent-cloud/app/src/components/AgentBuilder.tsx,products/agent-cloud/app/src/index.css | verify=`npx vitest run src/components/IntentComposer.test.tsx` | Build and test the supervised composer UI.
- [x] T5 | slice=products/agent-cloud/app/public | files=products/agent-cloud/app/public/.well-known/agent-card.json,products/agent-cloud/app/public/.well-known/runtime-compatibility.json,products/agent-cloud/app/public/index.html,products/agent-cloud/app/public/styles.css | verify=`npm run build` | Publish runtime discovery and public product explanation.
- [x] T6 | slice=products/agent-cloud/app | files=products/agent-cloud/app/docs/PORTABLE_AGENT_COMPOSER.md,products/agent-cloud/app/README.md,products/agent-cloud/app/scripts/release-qualification.mjs | verify=`npm run verify` | Document and qualify the deployable package.
