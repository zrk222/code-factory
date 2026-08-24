# Plan: agent-oven-outcome-exchange-v1
Spec: specs/agent-oven-outcome-exchange-v1.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Freeze the offer catalog and deterministic contract/verdict domain.
2. Add tenant-scoped contracts, evidence, verdicts, and exact credit reservations.
3. Add authenticated lifecycle APIs and machine-readable discovery.
4. Add a first-class Exchange UI and public value summary.
5. Prove happy path, replay, insufficient credit, recursive delegation, hollow evidence, self-verification, cancellation, and single settlement.

## Tasks (atomic - each independently shippable)
- [x] T1 | slice=docs | files=docs/AGENT_ECONOMY_RESEARCH_2026.md | verify=`specline validate agent-oven-outcome-exchange-v1 --root .` | Seal the official-source research and product boundary.
- [x] T2 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/agentExchangeDomain.ts,products/agent-cloud/app/convex/agentExchangeDomain.test.ts | verify=`npx vitest run convex/agentExchangeDomain.test.ts --maxWorkers=2` | Implement catalog, canonical contract, state transitions, and deterministic evidence verifier.
- [x] T3 | slice=products/agent-cloud/app/convex | files=products/agent-cloud/app/convex/schema.ts,products/agent-cloud/app/convex/agentExchange.ts,products/agent-cloud/app/convex/agentExchange.test.ts | verify=`npx vitest run convex/agentExchange.test.ts --maxWorkers=2` | Implement tenant-scoped hire-to-settlement lifecycle and schema.
- [x] T4 | slice=products/agent-cloud/app/src | files=products/agent-cloud/app/src/components/AgentExchangePanel.tsx,products/agent-cloud/app/src/components/AgentExchangePanel.test.tsx,products/agent-cloud/app/src/App.tsx,products/agent-cloud/app/src/App.test.tsx | verify=`npx vitest run src/components/AgentExchangePanel.test.tsx src/App.test.tsx --maxWorkers=2` | Add discover, hire, supervise, and first-class navigation.
- [x] T5 | slice=products/agent-cloud/app | files=products/agent-cloud/app/src/index.css,products/agent-cloud/app/src/PublicLanding.tsx,products/agent-cloud/app/public/.well-known/agent-card.json,products/agent-cloud/app/public/.well-known/outcome-agent-contract.json | verify=`npm run build` | Add responsive public polish and machine-readable discovery.
- [x] T6 | slice=products/agent-cloud/app | files=products/agent-cloud/app/README.md,products/agent-cloud/app/docs/OUTCOME_AGENT_EXCHANGE.md | verify=`npm run verify:release` | Document deployment and verify the release boundary.
