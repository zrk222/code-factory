# CF daily-driver upgrade decisions

Research date: 2026-10-14. Status: research and implementation priorities, not shipped functionality or measured productivity. Repository basis: `2f00b23`; unrelated pending WebMCP changes are outside this record.

## Product decision

### Local workflow update — October 16, 2026

The following describes the current source implementation. It is separate from
the research priorities below and does not establish public-package availability.

1. Declare the requested behavior and acceptance cases before implementation.
   Bind each case to its inputs, candidate sources and expected outcome.
2. Capture the approved original and deliberately broken production code through
   the existing bounded local mutation runner. Use the same selected assertion
   and an unrelated control; collection, setup and infrastructure errors do not
   count as successful behavioral challenges.
3. Close the mission and verify its current evidence. Supported unit,
   requirement-mutation and receipt-trace gates derive their observations from
   the captured executions and their digest lineage. A generic `passed` field
   cannot satisfy these gates. Missing or unsupported required gates keep the
   mission incomplete.
4. Read the local completion summary through the existing CLI:

   ```text
   factory proof-card PATH_TO_COMPLETION_JSON --root REPOSITORY --local-details
   ```

   Add `--json` for agent consumption or `--out-dir DIRECTORY` to choose a
   workspace-contained output directory. These are local JSON and Markdown
   details, including task text and paths. The default privacy-safe share-card
   route remains separate.

The summary shows requested behavior, checked cases, expected and observed
outcomes, files checked, unfinished work, unexamined scope, human review and one
next action. It re-verifies evidence on refresh; stale evidence becomes invalid,
and a mission changed during rendering is rejected. Files checked are not an
actual Git diff: inspect that diff separately to establish applied changes.

Local captured execution assumes a writable local host and is not independent
attestation. Signer-verified statements have a separate disposition. Neither
establishes that the specification is sufficient or that production is correct.
The bounded non-UI journey has retained original-pass, natural mutant-failure,
unaffected-control and stale-snapshot checks. Browser, accessibility, responsive
layout and live integration requirements still need their own applicable
evidence; the UI journey remains incomplete when those checks are absent.

The retained positive verifies in a fresh process under its captured execution
profile, including pytest's injected `PYTEST_VERSION=9.0.2` and disabled plugin
autoload. The local-details CLI also returns COMPLETE in that matching profile.
A different environment is rejected as drift. These observations establish this
profile only; they do not establish portable execution across environments.

External review-claim normalization and full Studio/MCP delivery remain separate
unfinished integration packets. No automatic approval or release authority is
introduced by this workflow.

Make CF the shortest reliable path from a development task to an understandable, verified change. Optimize accepted working changes, review effort and recovery time. Preserve depth across every applicable audit family while making specialized controls discoverable only when needed. Use existing modules before adding abstractions; retain the 460 Python-file cap and existing size guards.

The daily experience should answer four questions: What changed? What is actually wrong? What should I do next? What evidence proves the repair? An inexperienced builder needs plain-language guided choices. An experienced engineer needs concise source locations, reproducible commands, independent observations and direct access to raw evidence.

## What practitioners are building

| Evidence | Observed pattern | Decision for CF |
| --- | --- | --- |
| [Reddit review-wall discussion](https://www.reddit.com/r/indiehackers/comments/1wo2ilu/are-coding-agents-creating-a-review-wall-or-am-i/) | Reviewers need task intent and manageable changes, not just generated diffs. | Put a short intent and acceptance summary beside each candidate diff; order work by risk and dependencies. |
| [Reddit hidden CI coverage discussion](https://www.reddit.com/r/indiehackers/comments/1wiuxio/pr_reviews_are_taking_longer_than_ever_are_you/) | Operators report green aggregate jobs that omit expected test tasks. | Count discovered, selected, started and completed checks separately; show omitted or empty execution explicitly. |
| [Reddit stateful integration discussion](https://www.reddit.com/r/indiehackers/comments/1vrbe6m/ai_made_code_cheap_to_write_not_cheap_to_verify/) | Integration failures involve retries, duplicate events and ordering despite plausible code. | Challenge state transitions and boundary failures; keep external provider effects inert unless separately authorized. |
| [Indie Hackers factory architecture](https://www.indiehackers.com/post/what-i-ve-learned-about-building-a-system-around-coding-agents-cf4f5998c3) | Isolation, context, execution, verification and delivery address distinct problems. | Connect those boundaries through one workflow; extra context cannot replace execution evidence. |
| [Indie Hackers implementation account](https://www.indiehackers.com/post/automated-software-factory-DDkxsUBT0IRjP1rIgoOD) | Staging and replayable provider interactions make failures inspectable. | Retain bounded reproductions and replay inputs; label replay separately from live behavior. |
| [OpenAI harness engineering](https://openai.com/index/harness-engineering/) | Repository maps, isolated app environments, observable behavior and mechanically enforced constraints enable agent work. | Make relevant context and runtime evidence directly accessible; maintain concise navigation and enforce boundaries in code. |
| [Anthropic application harness experiment](https://www.anthropic.com/engineering/harness-design-long-running-apps) | Explicit completion contracts and running-app evaluation find failures; extra harness components can become costly and redundant. | Negotiate testable outcomes, validate actual workflows and remove overhead only through controlled component comparisons. |
| [Anthropic evaluation guidance](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents) | Deterministic, model and human graders serve different purposes; capability and regression evaluations differ. | Use executable checks for hard facts; calibrate JEV judgments and preserve uncertainty. Keep improvement experiments separate from regression protection. |
| [Cursor cloud-agent engineering](https://cursor.com/blog/cloud-agent-lessons) | Reliable environments, durable task execution and separate machine/conversation state support long-running work. | Preflight execution prerequisites, checkpoint bounded tasks and recover interrupted actions without repeating external effects. |
| [Martin Fowler on agentic engineering](https://martinfowler.com/bliki/AgenticEngineering.html) | Humans remain responsible for outcomes and inspect code, tests and other sensors. | Present evidence that supports accountable review and domain intent; agent agreement alone cannot establish correctness. |
| [Matklad on architecture maps](https://matklad.github.io/2021/02/06/ARCHITECTURE.md.html) | A short map helps contributors locate the right code without reading an implementation encyclopedia. | Generate task-specific navigation from maintained architecture boundaries; keep introductory guidance small. |
| [ExperiencedDevs discussion](https://www.reddit.com/r/ExperiencedDevs/comments/1wu1tzt/giving_your_codebase_entirely_to_the_ai/) | Engineers discuss maintainability, duplication and reviewable changes; opinions differ on model limits. | Preserve understandable changes and module budgets; do not adopt anecdotal line thresholds as universal model limitations. |

Community posts are qualitative, self-selected accounts; some authors promote services. Vendor accounts are useful implementation evidence, not independent comparative performance studies. Dates shown by community pages may be relative. No source establishes CF accuracy, market demand or a 10x gain.

## Existing CF capabilities and the actual integration gaps

Source inspection is bounded. A symbol establishes an implementation surface, not successful end-to-end execution, complete scanner coverage or current public-package availability.

| Existing anchor | Established surface | Remaining work |
| --- | --- | --- |
| `docs/OVERVIEW.md` | Guided first use and Graph Ops discovery. | One compact recurring action view instead of requiring users to navigate product terminology. |
| `factoryline/proof.py`: `risk_for_paths`, `replay_plan` | Changed-path risk and replay planning. | Connect selection to the normal daily operation and show why each required check runs. |
| `factoryline/proof_reuse.py`: `plan_proofs` | Input/tool/environment-bound proof planning. | Join reuse with risk selection; surface RUN/REUSE/SKIP/BLOCK and reject stale evidence. |
| `factoryline/context_efficiency.py`: `build_selected_context_packet`, `evaluate_context_experiment` | Selected context and paired experiment evaluation. | Give each task compact fresh source context; establish benefits from comparable runs rather than estimated tokens. |
| `factoryline/repair_sandbox.py`: `execute_approved_repair` | Owner-approved bounded repair lifecycle with authority checks and attempt records. | Verify the unified scan-to-repair-to-recheck path, interruption handling and unchanged primary checkout on failed attempts. |
| `factoryline/audit_trace.py`: `build_audit_trace`, `verify_audit_trace` | Trace construction and verification. | Ensure enrolled adapters capture actual outputs, missing payloads, truncation and termination; receipt presence is not capture completeness. |
| `factoryline/first_lap.py`: `record_incident`, `promote_incident` | Incident records and compiled regression requirements. | Join failure capture to replay and executed permanent regression checks; promotion alone does not execute a test. |
| `factoryline/agentic_control.py`: `route_model` | Descriptive model-tier selection; no provider call. | Connect authorized host adapters to measured outcomes, bounded escalation and real usage observations. |
| `factoryline/runtime_audit_common.py`: `execute_native_challenge` | Bounded native challenge execution. | Complete applicable families and preserve positive, negative and disabled-rule evidence with current origins. |

## Ordered delivery packets

Each packet extends existing surfaces, has bounded changes and receives its own source-bound proof. These are acceptance requirements, not achieved measurements.

### P0-A: substantive execution and reliable findings

- Complete the currently failing OSV native-control route before adding new scanner engines. Preserve its first failure and raw diagnostic evidence. Successful image build or CVE verification does not establish native control success.
- For every selected lane, show supported scope, inventory totals, exclusions, executed rule identifiers, native engine/config identity and missing evidence. Never summarize empty, timed-out or truncated execution as clean.
- Keep confirmed defects, unsupported static suspicions, explicitly declared smoke/type/benchmark intent and incomplete evidence distinct. Require runtime or checker evidence when static analysis cannot establish callback execution.
- Acceptance: positive controls fire; negative controls remain clear; disabled controls prove the detector matters; stale source/configuration is rejected; missing and truncated outputs remain incomplete. Preserve known genuine detections.

### P0-B: one daily action view

- Reuse the existing front door and Mission Control to show changed files, highest-priority actionable findings, required next actions and verification gaps. Keep advanced lane names in details.
- Show one primary action appropriate to current state: inspect, run required checks, prepare repair, resume or review evidence. Never imply that a prepared plan executed.
- Use selectable explanations plus a custom answer for inexperienced operators. Experts can inspect exact commands, sources and raw receipts directly.
- Acceptance: first use on a real repository produces understandable results without teaching internal vocabulary; measure time to first useful finding, task completion and unresolved questions. Do not promise a sub-minute result before observation.

### P0-C: changed-code verification with exact reuse

- Combine risk planning with existing proof reuse. Build a dependency-aware check workset; reuse unchanged valid proofs, rerun failed or invalidated checks and explicitly account for unaffected checks.
- Global/toolchain/configuration changes invalidate all dependent proofs. A path heuristic cannot silently suppress a mandatory audit family.
- Acceptance: changed source, dependency, configuration or environment causes the corresponding rerun; intact bindings reuse; ambiguous dependencies run; no required check disappears. Record observed elapsed time and executions avoided.

### P1-A: approved repair with resumable recovery

- Connect findings to existing isolated repair execution. Present affected paths, behavioral intent, expected verification and rollback boundaries before approval.
- Persist failure phase and attempt identity. Resume from verified state; require fresh authorization when scope changes. Preserve developer edits and failed candidates for diagnosis.
- Acceptance: interruption, timeout, concurrent edits, stale approval and failed recheck cannot promote a repair; the primary checkout remains protected; duplicate callbacks cannot repeat external effects.

### P1-B: runtime workflow challenges and regression learning

- Add focused contracts around authorization, webhooks, migrations, retries, resource exhaustion, timeouts, race/interleaving cases and nested failure propagation through existing native profiles.
- Connect recorded failures to incident promotion, reproducible replay and explicit regression execution. Label synthetic/replayed/live evidence independently.
- Acceptance: missing signatures, duplicate events, out-of-order events, partial writes, cancellation and dependency failures produce their declared outcomes; successful recovery preserves state invariants.

### P1-C: smaller-model execution with calibrated JEV

- Give a smaller model a source-bound task packet, explicit allowed paths, exact acceptance checks and a bounded repair budget. Escalate on reproducible failure or unresolved risk, not agent confidence.
- JEV receives original intent, current diff, relevant source, actual findings, execution evidence and omissions. Return supported/refuted/insufficient evidence per proposition with cited locations and versioned rubric/model metadata.
- A judge cannot clear a deterministic failure or supply missing execution. Use disagreements to request the missing observation, not manufacture consensus.
- Acceptance: compare equivalent tasks and environments; measure accepted outcomes, review effort, latency and actual billed usage where available. Track abstentions/corrections. Frontier-like results and savings remain hypotheses until these comparisons support them.

### P1-D: review that is quick to understand

- Assemble a concise intent-to-diff-to-evidence handoff with stable finding IDs, fixed/reopened status, exact reproduction and verification commands, and relevant trace/screenshot links.
- Keep source-bound decisions and compact architecture maps accessible to agents; do not inject completed plans or large run JSON into every session.
- Acceptance: reviewers can locate the behavior change and evidence without reconstructing the chat; measure reviewer minutes and follow-up questions alongside escaped defects.

## UI value and release criteria

Show actual confirmed defects, evidence gaps, checks executed/reused, verified repairs, failed attempts, elapsed time and measured usage. Unknown accuracy, tokens, cost and savings remain unknown. Display source and environment freshness beside results. No aggregate quality grade can conceal an incomplete mandatory check.

Measure accepted-change cycle time, review time, time to first useful result, repair success and reopened defects. Evaluate harness components one at a time; remove duplicated machinery only when the same acceptance checks retain their outcomes. Keep runtime dependencies and generated artifacts bounded. Do not import cloud orchestration infrastructure until an observed requirement justifies it.

No automatic publication, deployment, signing or merge authority is added. External accuracy adjudication remains paused under the operator's instruction; this research does not restart it or establish precision/recall. Public previews may describe only installed and verified capabilities; future workflow behavior must remain labelled planned.

## Immediate next work

1. Resolve the failed OSV control with real retained native evidence.
2. Finish the pending read-only WebMCP projections and registry metadata checks.
3. Implement P0-B and P0-C as small integration packets, then P1-A through P1-D against the acceptance requirements above.

This record adds research decisions to the existing remaining-goal scope. It does not mark that goal complete or replace unresolved work with a new feature list.
