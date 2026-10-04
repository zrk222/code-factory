# ADR 0014: Budget for the 0.47.0 audit modules

## Status

Accepted by the repository owner on 2026-10-04.

## Context

The architecture gate reported 460 Python files against a frozen limit of 454.
The increase is the 0.47.0 audit implementation: runtime coverage receipts,
GitHub account overview, Junie review and taxonomy, audit trace and action
references, workflow audit, architecture guard, and the CI receipt writer.
Their focused tests were consolidated into existing test modules, reducing the
candidate from 473 Python files to 460. The gate still rejected the candidate.

## Decision

Set `max_python_files` to 460, the measured count of this candidate. This is a
six-file budget adjustment to admit the named, reviewed audit surfaces. Update
the existing file-size ceilings for `audit_trace.py`, `benchmark_lab.py`,
`github_account_overview.py`, `junie_review.py`, and `mcp.py` to their measured
candidate sizes. These are exact ceilings, not added headroom. No other file
ceiling changes. Any further growth in these files or the Python inventory
blocks until another explicit architecture decision. The gate continues
measuring repository inventory without suppressions or waivers.

## Evidence required

- `factory architecture health --json` must report `decision: HEALTHY`.
- The consolidated audit tests and architecture-health tests must pass.
- Ruff lint and format checks for the changed Python test modules must pass.
- Exact line and normalized-byte sizes are bound by `architecture-policy.json`.

## Consequences

- The current 0.47.0 candidate can be evaluated without silently raising the
  cap or suppressing the Python-file metric.
- The repository has no remaining Python-file growth allowance; future module
  additions require consolidation or a separately reviewed decision.
- The five adjusted files have no additional size allowance beyond this
  candidate; further growth still blocks the gate.
- Release cadence, protected CI, specialist-agent review, and publisher checks
  remain independent release gates.
