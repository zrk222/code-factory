# Agent contracts and evidence rails

Code Factory keeps agent customization reviewable at the Core 5 seam: model,
prompt, tools, harness, and handoff. A contract is a small JSON manifest,
validated by `factory agent contract`, canonicalized, and bound to a SHA-256
digest. It describes what an agent may use; it does not contain credentials
and it does not grant deployment or provider-spend authority.

```bash
factory agent contract .factory/agent-contract.json --json
```

The contract enforces a 12,000-token context ceiling, a 5,000 ms model-latency
ceiling, and a $0.50 per-run ceiling. Tool allow/deny sets must be disjoint;
isolated context walls cannot include creator scratchpads or hidden reasoning.
When `.factory/agent-contract.json` exists, `factory assemble` validates it
before any module is run and fails closed on drift or an invalid rail.

## Tiered model-route receipts

CF’s agent-access plane uses three deterministic routing tiers:
`lightweight`, `workhorse`, and `frontier`. `route_model` selects a tier from
explicit task, risk, latency, and token inputs; it never contacts a provider or
grants model authority. The returned `factory.model-route.v1` receipt is
SHA-256 bound and can be independently checked with `verify_model_route`.
Orchestrator plans reject unknown tiers before workflow admission. To detect a
validly re-sealed route that no longer matches the current rule, use:

```bash
factory agent route-audit path/to/model-route.json --json
```

The route audit verifies the receipt, recomputes the expected tier, and emits
a hash-bound `MATCH` or `POLICY_DRIFT` result. It does not call a model or pick
a provider. This keeps tiered model allocation observable without turning
model choice into an unmeasured cost, quality, or execution claim.

Creator/verifier missions additionally carry an adapter attestation. The
attestation binds the mission digest, distinct creator/verifier identities,
fresh-session state, an isolated context wall, and an evidence digest:

```bash
factory agent attestation .factory/missions/<id>/adapter-attestation.json --json
```

Mission completion refuses to close without this receipt. The receipt proves
that the adapter supplied the declared wall; it does not claim that the
external model or provider was called.

## Telemetry reconciliation

FactoryLine reconciles `receipts/`, `.factory/runs/`, `.factory/traces/`, and
`.factory/meter.jsonl` without publishing feature names, prompts, paths, or
raw logs:

```bash
factory telemetry inventory --root . --json
factory metrics --root . --json
```

Conflicting run identities are surfaced as conflicts. Missing cost, token, or
queue telemetry remains unknown; it is never turned into zero or a savings
claim. Receipt discovery reuses the local hash-bound receipt index when fresh,
otherwise performs a bounded scan. Parsed JSON is memoized by content digest,
so same-size/same-timestamp changes are not mistaken for a cache hit. The
inventory reports when a source reaches its configured file bound.

## Lifecycle measurements

`factory metrics --root . --json` validates each CLI lifecycle receipt's
content digest before aggregation using bounded parallel reads, and reports
coverage, invalid-receipt counts, and observed p50/p95/max elapsed time overall
and by top-level command family. These are local invocation measurements only;
they are not provider latency or productivity claims.

## Unified native audit operation

Use `factory scan --root PATH --deep --json` for the local audit overview.
For authorized native execution, add `--worker-config PATH` with signed,
SHA-pinned worker configuration. Select workers for the repository languages
and risk: CodeQL Python, JavaScript/TypeScript, or GitHub Actions; Semgrep's
Python and JavaScript/TypeScript rules; dependency, secret, configuration,
runtime and fuzz workers as applicable. MCP status tools read evidence;
they do not launch these workers.

Bind findings and repair instructions to candidate, profile, tool and image
hashes. Retain native SARIF flows and reproductions. Rerun affected checks after
a repair, then obtain separate specialty AI review. Reuse evidence only when
its complete candidate and execution bindings match; an inventory or stale
receipt is never a pass. Missing runtime, mutation or language coverage stays
incomplete. Avoid launching every heavyweight worker for each edit.

## Current accuracy operations (Study249)

This dated snapshot is the shared operational reference for the Study249
accuracy sample. The 55% is actionable precision on this sample, not a general
precision guarantee or universal coverage claim.

- The candidate sample recorded 33 true positives, 27 false positives, and no
  unclear labels: 55% precision (Wilson 95% interval 42.49-66.91%). The
  baseline recorded 33/43 true positives (76.74%; Wilson interval
  62.2555-86.8463%, rounded to 62.26-86.85%). On the 43 unchanged exact claims, both recorded 33 true
  positives and 10 false positives, so the common-claim measured gain was
  zero.
- 32 of 33 candidate true positives were distinct sink locations in one
  repository. Two blinded same-model GPT labelers agreed. The human release
  owner separately validated and accepted the reported result; there was no
  separate human packet-label submission or external-organization validation.
  Study249 was prospectively frozen before prediction and labeling. After
  measurement it became exposed development data for future tuning, so it is
  not fresh evidence for later tuning claims. The baseline timed out on 17
  candidate-only sampled alerts; those unmatched alerts do not show paired
  gains or regressions.
- The release owner previously accepted the observed 55% result for the
  current bounded release decision and authorized publication. The latest owner
  instruction **supersedes that publication authorization**: finish the PR #255
  merge after its required checks pass, then **hold publication until the next
  precision PR (requested as PR #256) is completed with higher measured scores**.
  Its target remains at least 80% actionable precision on a new prospectively
  frozen, sufficiently decided sample. PR #256 was not yet present at the time
  this hold was recorded. Do not dispatch the publish workflow, create a public
  release, or upload packages for PR #255 while this hold applies.
  Owner acceptance does not establish that publication occurred or provider
  checks passed. The current technical checks remain enforced. Do not claim
  the higher target has been reached without its own evidence.
- Keep the configured caps at 464 Python files and 133 core modules. Prioritize
  precision, speed, and simplicity. Preserve finding IDs, severity, and test
  expectations. Reproduce actual failures, misses, and false positives; do
  not turn frozen exposed data into a fresh general-gain claim.

Agent taxonomy and generated IDE manifests link here. Keep dated measurements
in this shared reference instead of copying them into generic agent rules.


The follow-up's one-time Astra High plan is recorded in
[`accuracy-efficiency174.md`](../plans/accuracy-efficiency174.md#next-precision-pr-one-time-astra-high-senior-security-plan)
and its [source/case census](evidence/astra-precision256-plan.json). Priorities
are resolved enum/discriminator roles, dominating immutable overwrite inputs,
and complete local fixture effects. These are planned changes; the current
measured score remains 55%. Retain all 33 exact TPs, then measure on a new
prospectively frozen cohort. PR #255 merge does not lift the publication hold.
