# Universal workflow audit
## MUST - Functional core
### Requirements (EARS)
- When a coding audit runs, the system shall return a project-neutral receipt binding the reviewed check catalog, candidate source hashes, observations and artifact hashes. `BIND`
- If any declared check/profile is missing, duplicated, unknown, FAIL or BLOCKED, the system shall reject the audit without executing project code. `COVERAGE`
- When PASS or N/A is recorded, the system shall reject missing reasons, execution identity, timestamps, artifact hashes or stale candidate/catalog references. `EVIDENCE`
- When evidence paths escape the workspace or change bytes, the system shall reject the audit. `PATH`
- When an audit receipt is emitted, the system shall keep execution, repair, approval, merge, publishing, credential and deployment authority false. `AUTHORITY`
- When an audit is INCOMPLETE or INVALID, the receipt shall include one actionable agent work item per error, with responsible role, exact check/profile when known, candidate binding, evidence to attach and a fail-closed stop condition; PASS receipts shall return an empty action list. `AGENT_ACTIONS`
### Acceptance criteria (Gherkin)
```gherkin
Scenario: Incomplete application workflow
 Given BIND and COVERAGE
 When a required failure-recovery case has no observation
 Then EVIDENCE and AUTHORITY reject the audit
Scenario: Reusable across declared project profiles
 Given PATH
 When a CLI and API project submit separate complete fixture observations
 Then BIND and AUTHORITY preserve their own profiles and requirements
Scenario: Missing evidence yields agent-ready remediation
 Given BIND and COVERAGE
 When a required check/profile observation is missing
 Then AGENT_ACTIONS names the check, profile, evidence to attach and agent role
 And the action is bound to the same candidate SHA as the receipt
 And the audit remains INCOMPLETE until current evidence is supplied
```
## Bounds
Read-only receipt evaluator. Exactly 0 incomplete checks required for PASS. It returns CLI 0 for verified evidence completeness, 2 for incomplete or invalid evidence. SHA256 has 64 hex characters. At least 1 check, profile and source required. Universal categories: happy_path, validation, failure_recovery, state_consistency, security_privacy, performance, accessibility and external_effects. Each declares applicable true or false with reason; applicable categories need a named check. N/A is allowed only for a reviewed inapplicable category with evidence. UTF-8 JSON uses existing Journey Proof workspace-containment and artifact hashing helpers. No runtime execution or certification from recorded labels alone. No new dependency.
Project-neutral includes CLI, API, frontend, library, mobile and data pipeline code. Each declares its required execution profiles; browser names are not hardcoded.

An inapplicable category must bind one current workspace-relative artifact with kind `review`. The receipt reports its hash and path. Hash presence does not authenticate the reviewer or validate the review judgment; the evidence must be inspected separately before relying on the decision. Contract/observation JSON inputs and individual artifacts are bounded to 16 MiB each, aggregate evidence hashing to 128 MiB, artifact references to 4096, and required check/profile pairs to 4096. JSON output has stable PASS/INCOMPLETE/INVALID states and the CLI returns nonzero for incomplete or invalid evidence.

The CLI has no graphical interface; accessibility here means stable machine-readable JSON states and actionable errors. External effects are inapplicable because the evaluator is local and read-only; the code and false authority fields must be reviewed to support that decision.

The evaluator assumes a stable local workspace for the duration of a run. Path containment is resolved before file open, so a concurrent hostile writer capable of swapping symlinks or targets is outside this evaluator's security guarantee. For untrusted or concurrently mutable workspaces, audit an immutable snapshot in an isolated runner. Do not describe this local check as a race-resistant sandbox.
Time parsing normalizes Z to +00:00 UTC; observations require an explicit timezone. Global routing scope includes C:\Users\rkatz\.codex\AGENTS.md, C:\Users\rkatz\.codex\skills\code-factory\SKILL.md and C:\Users\rkatz\.codex\routers\workflow-qa.md. The source CLI entry is python -m factoryline.cli from this checkout until a verified installed release exposes workflows. Installing or publishing the whole package is not part of this bounded change.
