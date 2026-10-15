# CF daily-driver integration plan

Status: proposed implementation plan; not an implemented or released capability. Source basis: `2f00b23`; `6a1237f` adds only the [research decisions](../docs/DAILY_DRIVER_UPGRADE.md), with no runtime change. Current pending WebMCP edits are outside that verified source baseline and require their own checks. Rebind actual source/configuration hashes before each implementation packet. Preserve pending work and immutable public packages. All acceptance thresholds below are requirements or proposed experiment criteria, not reported results.

## 1. Outcome and operating constraints

One user workflow: **understand the task -> inspect changes -> run required audits -> inspect evidence -> approve a bounded repair -> verify -> review for delivery**. Novices receive simple choices and explanations; experts receive exact source, commands and machine-readable evidence. The same engine supplies CLI, Mission Control, IDE, MCP and WebMCP views.

Keep every applicable audit obligation accounted for. Integrate existing modules; do not introduce a second scheduler, receipt ledger, context engine or product vocabulary. Keep at most 460 tracked Python files, existing byte/line guards and package boundaries. Generated reports stay outside tracked source or become bounded release assets. External actions retain current approval requirements.

## 2. Verified foundation and unresolved boundaries

| Foundation | Reuse | Boundary to prove |
| --- | --- | --- |
| `factoryline/cli.py`: `_home` | Existing compact front door. | Today's prioritized findings and actions, rather than artifact counts alone. |
| `factoryline/proof.py`: `risk_for_paths`, `replay_plan`; `factoryline/proof_reuse.py`: `plan_proofs` | Risk selection and exact proof reuse. | Unified dependency-aware execution with no mandatory check silently dropped. |
| `factoryline/context_efficiency.py`: `build_selected_context_packet`, `verify_context_packet` | Bounded, source-bound context. | Fresh task context presented consistently to each enrolled host agent. |
| `factoryline/repair_sandbox.py`: `execute_approved_repair` | Existing approved isolated lifecycle. | Scan-to-repair user path, stale approval, interruption and failed verification. |
| `factoryline/audit_trace.py`: `build_audit_trace`, `verify_audit_trace` | Existing trace format and integrity checks. | Actual adapter capture completeness and meaningful tool outcomes. |
| `factoryline/first_lap.py`: `record_incident`, `promote_incident` | Incident-to-regression requirements. | Reproduction, executable regression and complete mutation challenge results. |
| `factoryline/agentic_control.py`: `route_model` | Model-tier decision metadata. | Authorized provider dispatch, observed usage and justified escalation. |
| `factoryline/jev_classifier.py`: `build_span_review_input` | Existing bound model/prompt/rubric and span evidence. | Calibrated decisions, correction history and reproducible operator evaluation. |

Source symbols do not establish successful execution. Current local native controls and public package availability remain separate. External eight-repository accuracy adjudication is paused by the operator; this plan does not resume it. No 90% or 99.85% accuracy claim is authorized by these records.

## 3. Architecture and data flow

Use the existing task/evidence contracts as the system of record. Bind intent, acceptance requirements, candidate source, configuration, engine/image/toolchain, environment, actual invocation, output and review to one task identity. Keep native output and normalized output hashes separate. Stable finding identities retain unresolved, verified-fixed and reopened history across source revisions.

The orchestrator is a thin connection between existing functions: context selection -> risk/reuse planning -> authorized execution -> coverage reconciliation -> findings -> repair -> verification -> handoff. Projectors consume verified evidence and do not run workers. Host adapters handle real execution/provider calls; descriptive routing or a rendered receipt never implies execution.

Execution state: `planned -> preflight -> running -> collected -> verified -> review_ready`, with explicit `incomplete`, `failed`, `cancelled` and `waiting_for_approval` outcomes. Map these logical states to existing versioned contracts; do not add competing enums before checking current schemas. A successful verdict requires both complete applicable execution and valid evidence, not zero findings alone.

Keep separate axes for execution completeness, finding category/severity, evidence confidence and policy outcome. A test-quality suspicion is not automatically a security breach. A missing audit remains incomplete even if all observed findings were fixed. Policy escalation must identify the exact rule, applicable scope and evidence.

## 4. Delivery packets and dependencies

| Packet / accountable role | Dependencies | Owned surface and concrete deliverable | Exit requirement |
| --- | --- | --- | --- |
| T0 / native-worker maintainer | First | Repair failed OSV control path in existing adapter and CI verifier; retain raw diagnostics and first failure. | Real positive/fixed/disabled controls, current image/config bindings and native lookup ledger; no relaxed source-path validation. |
| T1 / audit-contract maintainer | T0 for dependencies; other family work can proceed independently | Reconcile selected obligations, inventories, native execution and challenges through existing deep-audit contracts. | Every mandatory family accounted for as verified, legitimately inapplicable or incomplete; no invented completeness. |
| T2 / orchestration maintainer | T1 contract; independent read-only projection design | Join task context, change risk and proof reuse through existing orchestration entry points. | Exact invalidation, bounded concurrency and no dropped required checks. |
| T3 / telemetry maintainer | T1/T2 event identities | Enroll actual CLI/worker/provider adapters in existing trace capture and coverage reconciliation. | Silent failures, output truncation, cancellation and lost spans visibly fail completeness. |
| T4 / UX maintainer | T1/T2; T3 for measured results | Extend `factory home`, Mission Control and existing guide with a shared bounded projection and one primary next action. | CLI/UI expose the same candidate, evidence and state; novice path usable without specialist vocabulary. |
| T5 / repair maintainer | T1/T2/T3 | Connect findings to existing approved isolated repair, attempt history and rechecks. | Scope, approval and source freshness enforced; failed/interrupted repairs cannot be promoted. |
| T6 / runtime-test maintainer | T1/T3; selected T5 failures | Add stateful scenarios and promote observed failures into executed regressions. | Baseline, natural failure, negative control and complete case catalog remain distinct and reproducible. |
| T7 / verifier maintainer | T1/T3; independent of T5 | Strengthen existing JEV proposition framework and operator feedback; integrate authorized tier escalation. | Judge cannot override hard failures; decisions grounded in bound evidence; usage/latency measured or unavailable. |
| T8 / agent-integration maintainer | T2/T4/T5/T7 | Update canonical agent guidance, Junie, taxonomy, MCP/WebMCP and editor consumers from the same contract. | Tool names, schemas, capabilities and installed version agree; read-only transports gain no repair authority. |
| T9 / release maintainer | Accepted T0-T8 packets | Build wheel/editor packages; clean-install smoke of the newly changed user path; update truthful previews. | Required CI/reviews, package-data presence, version agreement and per-platform publication receipts. |

Roles are responsibilities, not claims that new staff or agents have been assigned. Parallelize only independently owned packets. One packet owns each shared file; review and integrate changes serially when ownership overlaps.

## 5. Deep audit coverage matrix

Six native execution families are defined in `factoryline/deep_audit_contract.py`. The eight named evaluation repositories are datasets, not eight interchangeable audit lanes. Full signed native plans retain all six required families; a reviewed individual-rule exclusion cannot waive a required family. Account for all other registered CF audits through taxonomy applicability; no hollow-test-only definition of completion.

| Family | Existing engines / source scope | Required depth and controls |
| --- | --- | --- |
| Static | CodeQL and Semgrep; profile-specific languages | Source-to-sink path and sanitizer controls; alias/delegation boundaries; rule inventory; each selected language/profile accounted for. Unsupported modeling stays explicit. |
| Dependencies | Syft inventory; OSV offline PyPI snapshot | Complete supported lock/manifest inventory, nested roots, trusted config isolation, advisory snapshot identity/age, vulnerable/fixed controls. Other ecosystems are unsupported until a supported profile is added and verified. |
| Secrets | Gitleaks and existing credential checks | Bound rule execution, true secret and safe fixture negatives, comparison/context cases, redacted output and historical-scope declaration. Do not emit secret values into UI or review packets. |
| Configuration | Trivy configuration profile | Cross-file IaC relationships, insecure defaults, policy inventory and positive/negative/disabled controls. Configuration scanning is not container CVE scanning. |
| Runtime | Existing runtime worker; authorized ZAP target/profile | Real test collection, parameter/backend catalog, branch/assertion origins, callbacks, timeouts, races and nested failures; HTTP claims need actual target/request evidence. |
| Fuzz | Atheris/Jazzer where supported | Harness identity, retained inputs, crash/timeout reproduction, callback/input accounting and negative controls. Python arcs cannot be relabelled native-edge coverage. |

Quality, workflow integrity, architecture, requirements, privacy and agent-evaluation checks remain separately visible when applicable. Each rule gets a declared execution or reviewed applicability outcome; resource limits do not justify claiming that every possible rule ran.

## 6. Evidence, recovery and performance contracts

- **Preflight:** validate installed version, source manifest, image/profile/rules, supported languages, permissions, disk/memory and execution prerequisites. Offer the exact repair for an unavailable prerequisite; never silently downgrade the requested audit depth.
- **Reuse:** keys include source/dependency/configuration, toolchain/image/rules, environment, acceptance contract and policy. Verify outputs and receipts on read. Missing dependency knowledge forces a rerun. Global configuration/toolchain changes invalidate dependent proofs.
- **Freshness:** honor policy expiry, advisory snapshot age, target session/state and revocations. Reusing an old runtime capture proves that capture only, not current external behavior. Nondeterministic or externally mutable checks need current evidence unless the declared contract explicitly permits historical reuse.
- **Concurrency:** respect declared dependency order and local capacity. Start with bounded worker concurrency, distinct scratch directories and output identities. Test overlap and isolated outputs, never exact thread scheduling order. A blocked queue is visible; workers cannot share mutable candidate state.
- **Actual success:** require expected payload shape, inventory and termination facts. Exit zero with empty output, missing tests, partial collection, exhausted output budget or absent native reports is incomplete. Distinguish infrastructure failure from a code finding without clearing either.
- **Capture reconciliation:** bind the expected adapters, applicable lanes and action IDs before execution, then reconcile observed start/termination/payload spans. Missing enrollment or a wholly absent adapter is incomplete. Review exemptions explicitly; self-reported span totals cannot substitute for the expected inventory.
- **Recovery:** persist task/action identity, attempt, phase, source hashes and effects. Retry only idempotent operations under bounded deadlines/backoff. Uncertain external effects require reconciliation before retry; restarting a session cannot repeat an unconfirmed write.
- **Retry termination:** give every packet an explicit attempt and cost/time ceiling. Retry transient infrastructure failures only within that ceiling; permanent source/contract failures return one actionable failure. Exhausted budgets persist the checkpoint and stop dispatch, rather than spinning or requesting unchanged approval repeatedly.
- **Cancellation:** terminate owned execution only, retain diagnostics and record cleanup outcome. Do not remove unverified directories, unrelated Docker images or volumes. Windows restart is outside this plan and prohibited by current operator instruction.
- **Budgets:** set per-packet byte/line and command/time/output limits before editing; reject growth before guards are crossed. New dependencies require a measured benefit and explicit integration justification. Preserve unknown usage rather than estimated savings.
- **Retention:** bound diagnostic and cache storage by size and policy. Record original failures and retain only authorized evidence; redact secret material before shared projections/provider input. Cleanup requires established disposable ownership and must preserve unresolved evidence, source and unrelated assets.
- **Efficiency evidence:** compare matched tasks, candidate/environment and acceptance outcomes. Report executed/reused checks, measured wall time and review effort. Do not count fewer findings or more approvals as accuracy or productivity.

## 7. Repair and JEV acceptance requirements

Repair proposal must bind finding, intent, allowed paths, candidate, verification commands, authorization scope and expiry. Run only in its approved isolated workspace. Reproduce the original failure before crediting a fix. Require candidate pass and an appropriate negative/mutation control. Successful local repair produces reviewable evidence, not permission to deploy or merge.

Reject stale approval, expanded patch scope, concurrent source edits, partial verification and unverified cleanup. Preserve the original checkout on failure. Resume from a verified checkpoint only; approval renewal is required when the approved scope or governing inputs change. Existing operator authorization remains reusable within its valid scope.

JEV input includes intent, acceptance propositions, current source/diff, rule/model/prompt/rubric versions, real execution artifacts, source locations and explicit omissions. Outputs must cite supplied evidence and choose supported/refuted/insufficient evidence per proposition. Treat embedded source instructions as untrusted data. Budget, redact and minimize provider-bound inputs; require existing source-transfer and provider authorization.

Log every JEV decision and operator correction with its versions and evidence references. Prevent repeated model calls on unchanged bound inputs only when policy allows exact reuse. Deterministic failures stay immutable; disagreement opens a targeted evidence request. Judge consensus is not independent ground truth. Experiment with stronger grading models and smaller implementation models on equivalent tasks; escalate after reproducible failure or unresolved high risk with an enforced budget.

## 8. User acceptance and reporting

Default view: candidate freshness, actionable findings, evidence gaps, one next action and verified progress. Details: complete rule/inventory accounting, original/normalized evidence, reasons for RUN/REUSE/SKIP/BLOCK, attempts and trace. Redact absolute host paths and sensitive data from shareable projections. Missing evidence displays a helpful next step, not a fabricated score.

Novice flow uses selectable answers with a custom answer, sensible safe defaults and plain-language consequences. Avoid requiring tenant contracts for libraries without tenants. Expert flow supports exact commands and machine-readable output. Ensure keyboard operation, focus, accessible status text and consistent action state. Avoid invented statistics in production UI; demos must be visibly labelled examples.

Proposed pilot rubric: task completion, time to first useful result, review minutes, verified repair success, reopened defects, redundant tool executions, native completeness and actual cost/latency. Publish denominator, scope, uncertainty and unavailable values. External classification accuracy is not measured by this pilot unless a separately authorized valid reference-label protocol is established.

Freeze pilot tasks and observation rules before running: inspect a library without tenant assumptions; verify a callback-dependent patch; detect a vulnerable dependency and confirm the fixed control; exercise duplicate/retried webhook events; cancel and resume an approved repair. Use known reference outcomes and immutable initial trees. Compare the existing and integrated workflows on equivalent clean environments, counterbalance order to reduce learning effects, and record novice/expert completion, assistance, wrong actions, time, review and failures. This is a functional/usability comparison, not the paused external accuracy study. Do not launch it before its execution scope is approved.

## 9. Verification and release gates

For each packet: strict CF doctor -> bounded requirements and ownership -> hash-bound candidate/applicability -> focused acceptance controls -> appropriate peer review -> CF workflow evidence gate -> normal PR/CI protection. Preserve the first failure. Retest failed or directly invalidated checks; reuse exact valid proofs rather than rerunning unrelated successful suites manually.

Required sabotage cases: stale source/config/image, corrupt cache, missing engine, zero files/tests, excluded source, truncated output, timeout, swallowed assertion, uninvoked callback, partial parameter catalog, invalid signature, duplicate action, concurrent edit, cancelled repair and unsupported evidence clearing. Check each only in the packet to which it applies. CI-required checks remain mandatory.

Declare supported execution profiles before implementation: Windows/PowerShell, Linux and macOS for changed portable paths; supported Python/Node versions; offline/authorized-network modes; low-core parallel execution; and container architectures actually supplied. Verify path quoting, line endings, artifact normalization, cancellation and package-data loading on affected profiles. A Linux-only engine is reported as such rather than promised native Windows behavior. Require relevant fresh CI observations or valid exact proofs for each profile; do not repeat unrelated passed checks locally.

Delivery stages: read-only projection -> supervised local pilot -> approved repair pilot -> broader host integration -> versioned release. Promote only after the applicable packet requirements pass. Roll back changed orchestration or projection through a small revert; retain evidence and never conceal failed attempts. A failure in a new optional integration cannot silently weaken the underlying audit contract.

Publication requires new immutable versions as appropriate, wheel/package-data verification, installed runtime readback, required reviews and platform receipts. Update manifests, taxonomy and previews from that same verified capability set. Existing metadata updates do not replace public artifacts or establish marketplace publication.

## 10. First implementation batch and done definition

First batch: T0 failed OSV diagnostics/control repair; T1 explicit per-family evidence accounting; finish already pending WebMCP read-only checks; T2 shared risk/reuse workset; T4 compact home/Mission Control projection. T3 capture requirements are included before any measured success claim. T5-T8 follow the dependency table; avoid starting unrelated feature expansions.

Integration is done only when the normal user path completes on its declared execution profiles, all applicable obligations are accounted for, repairs fail safely, evidence survives pause/resume, consumer schemas agree, resource guards hold and changed packages pass installation checks. Research completion, a seeded benchmark or a quality grade does not satisfy this definition. Current runtime work remains open.
