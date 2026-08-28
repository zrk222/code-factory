# Agent Recipe Lab

Agent Recipe Lab turns agent configuration into a supervised, evidence-driven search. It does not run arbitrary optimization inside Convex and it never promotes a recipe automatically.

## Six-stage user journey

1. **Use case** — describe one measurable job for the agent.
2. **Evaluation set** — bind an opaque object reference and digest to tenant-owned examples.
3. **Search space** — choose allowlisted provider/model identifiers, retrieval depths, memory modes, and authority modes.
4. **Guardrails** — set trial count, total credits, per-trial credits, grace checkpoints, quality floor, latency ceiling, and objective weights.
5. **Optimize** — Convex creates deterministic candidate contracts. Trusted hosted workers claim one trial, reserve cumulative credits through checkpoints, execute in an isolated sandbox, and return digest-bound evidence.
6. **Review** — Convex removes ineligible trials, computes the quality/cost/latency Pareto frontier, and proposes a deterministic weighted champion for independent approval.

## Trust and cost contract

- Policy violations prune a trial immediately.
- Credit must be reserved in a checkpoint before corresponding provider work.
- A trial cannot report final cost above its last reservation.
- Quality pruning starts only after the declared grace checkpoints.
- Only completed trials with zero policy violations and all hard constraints satisfied are eligible.
- The study creator cannot approve the champion.
- Approval records the exact recipe digest but does not activate, publish, or deploy the recipe.

## Hosted-worker boundary

Convex is the system of record for studies, candidates, reservations, outcomes, frontiers, and approval. A production worker adapter must:

1. authenticate as trusted infrastructure;
2. claim one queued trial;
3. resolve BYOK credentials from the existing opaque provider binding;
4. fetch the evaluation set by object reference outside Convex;
5. call `recordCheckpoint` before each bounded evaluation segment;
6. stop when the control plane returns `RECIPE_TRIAL_PRUNED`;
7. call `completeTrial` with exact metrics and an evidence digest; and
8. retain raw prompts, examples, outputs, and credentials outside recipe-study records.

The current deterministic candidate generator is the safe baseline. A future TPE or ASHA proposal service can run in the hosted worker, but every proposal must still fit the published search space and the same checkpoint, evidence, budget, and approval contract.

## Evidence boundary

Local tests prove control-plane behavior, authorization, redaction, constraint enforcement, Pareto selection, and UI accessibility. They do not demonstrate provider quality, measured savings, or a production optimization deployment.
