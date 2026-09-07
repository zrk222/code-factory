# 0.46.3 senior-engineering integration

## Audience and mission

For a developer or review team handing work from an AI coding agent to Code
Factory: make the observed behavior, defect sensitivity, and proof-routing
decision inspectable before a human approves the change.

## Story spine

- **Mission:** ship a change that satisfies the request, not merely a green
  command.
- **Tension:** the worker can choose weak tests, hide a real defect, or reuse a
  proof after dependencies changed.
- **Guidance:** 0.46.3 adds seven narrow, provider-neutral controls above the
  existing six audit lanes.
- **Agency:** a reviewer can inspect the exact attestation, replay metadata,
  dependency closure, and incremental/full comparison before choosing the next
  action.
- **Transformation:** an observation is either verified, incomplete, blocked,
  or required to run; a benchmark is PASS or BLOCKED; reuse is never inferred
  from an unknown dependency.
- **Celebration:** every receipt is bounded, content-addressed, and explicitly
  retains human release authority.

## What changed and the result it enables

| Control | Problem it prevents | Observable result |
| --- | --- | --- |
| Independent execution attestation | A worker's self-reported run being mistaken for independent evidence | DSSE + trust-root verification binds candidate, plan, runner executable, nonce, cleanup, memory, latency, and artifact digests. Local/supervised evidence cannot satisfy the independent lane. |
| Real-defect benchmark lab | A checker that passes synthetic examples while missing known failures | A human-owned buggy/fixed corpus produces case-level findings plus per-category precision/recall; a missed defect or broken fix is `BLOCKED`. |
| Dependency-aware scheduler | Reusing a green proof after an input, dependency, assurance level, or side-effect boundary changed | A topological plan emits `RUN`, `REUSE`, `SKIP`, or `BLOCK`; unknown closure and side effects fail closed. |
| Shadow comparison | An incremental shortcut silently omitting an obligation | Incremental and full supplied plans are compared for exact obligations and findings before any skip is reviewed. |
| Independent replay runner | A candidate cannot be reproduced with the exact source, dependencies, policy, and inputs that produced the failure | `factory senior replay` runs only an explicit argv in a fresh temporary workspace/process with a secret-free environment, contract digest, bounded output, cleanup, and a runnable reproducer. This is process isolation, not a kernel/container sandbox. |
| Executable repair comparison | A green fix hides that the original failure never reproduced or that a negative case was weakened | `factory senior repair` evaluates original failure, proposed repair, and negative controls together. Changed expectations require a named human reviewer and reason. |
| Evidence-reuse explanation | A proof is reused because its key looks familiar while policy, dependencies, toolchain, or environment drifted | `factory senior reuse` compares every declared fingerprint and explains `REUSE`, `RUN`, or `BLOCK`; missing or unknown inputs always force execution. |
| Failure briefing | A raw red receipt leaves reviewers to reconstruct impact and the next move | `factory senior brief` produces `what broke`, affected scope, a runnable reproducer, next fix, uncertainty, and receipt-linked evidence without guessing ownership. |

## Use it

```powershell
# Verify a signed external observation (no command is executed)
factory senior attest attestation.json --trust-root trust-root.json

# Evaluate observations already collected by the approved benchmark runner
factory senior benchmark benchmark.json --observations observations.json --out .factory/benchmark.json

# Route proof work from a declared dependency DAG (planning only)
factory senior schedule incremental.json --root . --out .factory/incremental.json
factory senior shadow .factory/incremental.json full-plan.json

# Reproduce a declared failure (only --execute runs the candidate)
factory senior replay replay-manifest.json --root . --execute --out .factory/senior/replay.json

# Compare original, repaired, and negative-control executions
factory senior repair repair-comparison.json --root . --execute --out .factory/senior/repair.json

# Explain why each proof is reused or rerun
factory senior reuse evidence-reuse-request.json --root . --out .factory/senior/reuse.json

# Turn a failed receipt into an evidence-linked briefing
factory senior brief .factory/senior/replay.json --out .factory/senior/failure-brief.json
```

Each command emits JSON with a schema, stable digest, action summary, and
`authority: none`; no command, provider upload, deployment, signing, or release
approval is performed by these adapters. An independent backend and a real
defect corpus remain supplied inputs and must be operated by the team's approved
runner. Missing or contradictory inputs are evidence gaps, not passes.

When receipts are saved below `.factory/senior/`, Mission Control / Graph Ops
projects them as read-only evidence nodes. It recomputes the receipt hash,
rejects symlinked or authority-claiming inputs, and adds a review marker for an
invalid, blocked, failed, unknown, or shadow-mismatched result; the visual
surface cannot execute, reuse, repair, or promote the receipt.

## Truth ledger

- **Observed:** the repository's tests exercise schema validation, failure
  handling, metrics, CLI routing, DAG cycles, and authority boundaries.
- **Sourced:** the adapters follow established ideas such as signed provenance,
  reproducible real-defect corpora, and content-addressed proof reuse.
- **Proposed:** teams can connect a hardened worker, BugsInPy/Defects4J-style
  fixtures, Testcontainers/Toxiproxy, Pact, or k6 through these bounded input
  contracts.
- **Unknown:** this package does not independently prove a hosted sandbox,
  production security, enterprise certification, or marketplace approval.
- **Boundary:** replay intentionally describes a fresh process and temporary
  workspace. It is not a claim of kernel, container, network, or credential
  isolation; provider runners must supply those properties and their own
  attestation.

## Next action

Run the focused tests and then connect one approved independent runner and one
small, reviewed defect corpus. Have a human review every `BLOCK`, `RUN`, and
`REUSE` decision before release.

## Verification receipt and known review boundary

- Full regression: `python -m pytest -q` — **1425 passed, 7 skipped, 2
  warnings**.
- Scoped ForgeLine QA: **A**, 16/16 units, maximum complexity 10, security
  score 100, composite 99.1. SpecLine strict validation, spec/plan gates, and
  all 14 validator mutants pass; the focused drift audit is 32/32.
- ForgeLine's installed adversary still records `A_SUBPROC` because it flags
  the literal word `subprocess` unconditionally. The replay implementation is
  intentionally explicit about this boundary: argv-only, `shell=False`,
  closed stdin, a minimal declared environment, bounded output, and no release
  authority. The finding is retained for human security review; it is not
  suppressed or presented as proof of a hardened sandbox.
