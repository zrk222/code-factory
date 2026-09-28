# Autonomous ops and native editor plan

Status: 0.47.0 candidate implements bounded editor audit views, the OpenCode
adapter, and a supervised Observer learning path on top of `factory learning`.
Automatic production skill edits remain disabled; owner promotion is required.

## Current editor slice

| Surface | Implemented in this candidate | Evidence boundary |
| --- | --- | --- |
| VS Code / Open VSX 1.0.2 | Explorer lane tree, cancellable local runs, source navigation, copied CF + ForgeLine summary | Five local observations; candidate UNBOUND |
| JetBrains 1.0.2 | Native CF + ForgeLine tab and Junie taxonomy route | User confirms each run; Junie is neither started nor monitored |
| OpenCode 0.1.0 | Native tools, `/cf-audit`, and post-change session hook | In-memory bounded results; no release authority |

JetBrains' [Junie review agent](https://junie.jetbrains.com/docs/junie-review-agent.html)
reviews a diff without running a build or tests. [Qodana](https://www.jetbrains.com/help/qodana/static-analysis.html)
adds static analysis and baselines. The FactoryLine route connects a candidate
to declared intent, negative controls, runtime evidence, and explicit gaps
beside those tools; it must not claim to have run Junie or Qodana. The
[JetBrains MCP server](https://www.jetbrains.com/help/idea/mcp-server.html)
offers IDE context when enabled by the user. FactoryLine's Junie project pack
only supplies local guidance and MCP configuration.

VS Code's [Testing API](https://code.visualstudio.com/api/extension-guides/testing)
and [agent hooks](https://code.visualstudio.com/docs/agent-customization/hooks)
offer later native report and trigger points. The 1.0.2 view uses explicit
commands and workspace trust. The [OpenCode plugin API](https://opencode.ai/docs/plugins/)
supports the native tool and session hooks used here.

## Executive briefing gap review (2026-09-28)

The attached briefing's earlier A/87.5 result is a dated snapshot, not current
release evidence. The published ForgeLine 0.10.7 artifact graded this checkout
**F/70.7** (complexity 18) and reported valid TSX as unsupported. The parser
corrections are now released as ForgeLine 0.10.8. Against this checkout the
published artifact returns **A/95.1**, max complexity 10, test-intent 0.89,
documented symbols 0.93, security score 100, and no parser or complexity
findings. CF 0.47.0 requires ForgeLine 0.10.8; `factory doctor --strict` checks
the installed version and exercises MJS, TS, and TSX QA so the older artifact
cannot report a healthy workflow. Repo-wide QA remains an inventory result;
feature QA still needs its SSAT and candidate-bound run.

| Briefing capability | Current CF/FL state | Remaining closure evidence |
| --- | --- | --- |
| Candidate-bound scrutiny and release | CF preflight, deep-audit receipts, architecture health, and protected review exist; the editor views report bounded observations | Run the exact candidate's required lanes, distinguish missing reports from passes, and retain the merge/release gate receipts |
| Dynamic user testing | Browser-flow evidence and runtime lanes can bind external observations | A separate authorized runner must execute real interactions against the candidate, attach artifacts, and show expected versus observed behavior |
| Mutation and counterfactual proof | CF has proof-of-survival and Counterfactual Arena routes | Execute candidate-specific mutants and alternative repairs; do not infer strength from a prior receipt |
| Deterministic YAML compilation and signed runtime artifacts | Harness Factory is a separate project; CF can inspect evidence but does not compile or run its artifacts | Define a versioned import/verification contract and independently validate hashes, signature, gate logs, and runtime identity before integration |
| Model routing and deferred context | CF issues deterministic model-tier receipts; agent contracts bound context | Build provider-backed execution and measured token/cost telemetry before claiming savings; implement versioned, task-scoped skill retrieval |
| Independent scrutiny | Specialty AI review is a separate protected check | Bind reviewer identity, candidate SHA, findings, and resolution to each release; evidence does not grant authority by itself |
| Observer skill learning | `factory learning` validates sealed forensic packets, requires DSSE-signed replay/holdout/false-positive and specialty-review receipts against an external offline trust root, then feeds owner-promoted versioned instructions into fresh task packets; superseded promotions are archived and owner rollback is hash-bound | Live provider authentication and independently measured real-task improvement remain outside the local receipt contract |
| ForgeLine multi-language depth | ForgeLine 0.10.8 is published; repo-wide QA returns A/95.1 and CF strict doctor passes its MJS/TS/TSX canaries | Repeat feature SSAT QA against the exact release candidate; repo-wide A does not substitute for it |
| Architecture capacity | `factory architecture health` is `HEALTHY` and the growth budgets remain enforced | Keep new CLI commands and modules within the existing budgets |
| Repository scope | Unrelated hosted-product source, plans, deployments, evidence snapshots, and generated dependencies are removed from this candidate tree | Published Git history still contains prior commits; this branch removes the content from the repository's current tree |

The briefing's "zero prompt-injection surface," 100% accuracy, millisecond
latency, and 25%/50% savings apply at most to stated fixtures or external
systems until independently measured here. CF/FL cannot certify defect absence
or promote a local inventory result to release approval. The earlier ForgeLine
F came from the stale 0.10.7 parser; the 0.10.8 published artifact now produces
the recorded repo-wide grade, which must still be reproduced on each final
release candidate.

## Observer Agent: implemented supervised flow and remaining proof

1. **Packet contract.** Normalize each Factory-B rejection into a
   `factory.forensic-rejection.v1` packet: immutable candidate SHA, source
   digest, failed mutation seed and expected/observed result, violated rule
   ID, counterfactual alternatives, validator versions, receipt hashes, and
   unknowns. Missing fields are `INCOMPLETE`, never inferred.
2. **Diagnosis.** An Observer proposes one root-cause hypothesis linked to
   packet facts and a replayable failure. It distinguishes weak assertions,
   implementation complexity, policy breach, and reviewer correction. A
   model's explanation is not proof of causality.
3. **Skill patch proposal.** The Observer writes a diff in an isolated branch
   against an allowlisted skill, template, or workflow specification. It cannot
   directly change production skill packages, release policy, or worker code.
   Each proposal states the target failure, generalizable rule, counterexample,
   and expected effect on future tasks.
4. **Replay and regression.** Run the old failing packet against the proposed
   skill and compare a holdout set of accepted tasks. Require a repaired
   rejection, no new severe false positives, no weakened oracle or scope, and
   bounded added context. Record the exact fixture and candidate hashes.
5. **Independent review.** A specialty AI reviewer, different from the
   Observer and worker, checks the packet, patch, replay, and holdout failures.
   The review is an evidence artifact; the owner controls merge and release.
6. **Deferred context.** Only a merged, versioned skill becomes eligible for
   Factory-A retrieval. Workers receive the smallest matching skill excerpt
   for the task and a skill version in their handoff. Existing runs remain
   pinned to the version with which they started.
7. **Rollback.** Superseding a promoted instruction archives its sealed
   promotion under `promotions/history/`. The task owner can restore a prior
   promotion by SHA-256 through `factory learning promote --restore`; a sealed
   rollback receipt records the source and restored versions. The archived
   record is never rewritten.

The packet schema and gates are implemented in `factoryline.learning_loop` and
the existing `factory learning` commands. Observer gate receipts are signed
DSSE envelopes checked against an explicitly configured offline trust root kept
outside the candidate workspace; runner keys need the `observer-gate-runner`
role, reviewer keys need `specialty-ai-reviewer`, and unsigned receipts,
untrusted signers, or wrong-purpose keys fail closed. This verifies signer
identity against the configured root, but it does not prove that a claimed
remote test run occurred or authenticate a live model provider session.
Promotion activates only task-scoped AKU instructions.
Superseded versions are immutable and rollback is owner-gated; real-task uplift
still needs separate replay and holdout evidence.

## First implementation packets

- Mutation survivor: require explicit state and boundary assertions, then
  replay the original mutant and a holdout that should still pass.
- Complexity violation: propose smaller modules in the planning skill; measure
  complexity on the resulting code and guard against merely moving branches.
- Review override: capture the reviewer correction with rationale and exact
  code context; do not teach the skill from an unverified override alone.

## Promotion gates

The local supervised loop is implemented. The broader claim that Factory-A
improves automatically remains unproven until real-task replay/holdout data and
authenticated specialty review are collected.
