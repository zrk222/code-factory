# Autonomous ops and native editor plan

Status: proposed architecture. The 0.47.0 source candidate implements the
bounded editor audit views and OpenCode adapter described below. The Observer
Agent and automated skill promotion are **not implemented** by this release.

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

The attached executive briefing is a useful target architecture, but its
numeric results and platform comparisons are not release evidence. The
ForgeLine `forge qa --repo-wide --root .` run against this candidate returned
**F, 39.4/100**, `max_complexity: 51`, and unsupported TSX parser results.
Its previous A/87.5 score, 0.74 test-intent ratio, and 0.77 documentation ratio
must remain dated snapshot claims. Repo-wide QA is inventory, not feature
admission; feature QA needs an SSAT and a candidate-bound run.

| Briefing capability | Current CF/FL state | Remaining closure evidence |
| --- | --- | --- |
| Candidate-bound scrutiny and release | CF preflight, deep-audit receipts, architecture health, and protected review exist; the editor views report bounded observations | Run the exact candidate's required lanes, distinguish missing reports from passes, and retain the merge/release gate receipts |
| Dynamic user testing | Browser-flow evidence and runtime lanes can bind external observations | A separate authorized runner must execute real interactions against the candidate, attach artifacts, and show expected versus observed behavior |
| Mutation and counterfactual proof | CF has proof-of-survival and Counterfactual Arena routes | Execute candidate-specific mutants and alternative repairs; do not infer strength from a prior receipt |
| Deterministic YAML compilation and signed runtime artifacts | Harness Factory is a separate project; CF can inspect evidence but does not compile or run its artifacts | Define a versioned import/verification contract and independently validate hashes, signature, gate logs, and runtime identity before integration |
| Model routing and deferred context | CF issues deterministic model-tier receipts; agent contracts bound context | Build provider-backed execution and measured token/cost telemetry before claiming savings; implement versioned, task-scoped skill retrieval |
| Independent scrutiny | Specialty AI review is a separate protected check | Bind reviewer identity, candidate SHA, findings, and resolution to each release; evidence does not grant authority by itself |
| Observer skill learning | Packet, replay, holdout, and promotion design below is proposed | Implement the entire loop with isolated skill patches, independent specialty review, rollback, and real-task validation |
| ForgeLine multi-language depth | Repo-wide inventory covers source paths but this run marked TSX parser unsupported and failed its quality gate | Provide the required parser in the ForgeLine environment, rerun full scope, resolve real complexity and security findings, then record a candidate-bound feature grade |
| Architecture capacity | `factory architecture health` is `HEALTHY`, but this checkout is exactly at the 184 CLI declaration, 454 Python file, and 659 Markdown file budgets | Reduce or consolidate existing surface before adding more files or commands; keep the budgets enforced |
| Repository scope | This checkout still tracks 200 files under `products/agent-cloud`, and repo-wide ForgeLine includes that separate product | Decide its repository boundary explicitly and audit it independently; changing scan scope alone cannot establish product separation or remove published Git history |

The briefing's "zero prompt-injection surface," 100% accuracy, millisecond
latency, and 25%/50% savings apply at most to stated fixtures or external
systems until independently measured here. CF/FL cannot certify defect absence
or promote a local inventory result to release approval. The current ForgeLine
F is an open quality gap, not a waived or redefined A.

## Observer Agent: next implementation slice

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
7. **Rollback.** A new rejection or measurable regression can retire a skill
   version and revert retrieval. Preserve the old packet, patch, replay, and
   decision to prevent a silent rewrite of history.

## First implementation packets

- Mutation survivor: require explicit state and boundary assertions, then
  replay the original mutant and a holdout that should still pass.
- Complexity violation: propose smaller modules in the planning skill; measure
  complexity on the resulting code and guard against merely moving branches.
- Review override: capture the reviewer correction with rationale and exact
  code context; do not teach the skill from an unverified override alone.

## Promotion gates

The Observer loop is complete only when packet validation, isolated patching,
replay, holdout comparison, specialty review, source-bound merge, and rollback
all work on real repository tasks. Until then, label it `PROPOSED`, and do not
claim that Factory-A improves automatically from Factory-B rejections.
