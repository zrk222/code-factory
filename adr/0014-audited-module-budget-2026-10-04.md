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

Set `max_python_files` to 465: 460 measured files plus a five-file reserve.
Update the existing line and byte ceilings for `audit_trace.py`,
`benchmark_lab.py`, `github_account_overview.py`, `junie_review.py`, and `mcp.py`
to five percent above each measured candidate size. This is bounded upgrade
headroom, not permission for unreviewed scope growth. No other file ceiling
changes. The gate continues measuring repository inventory without
suppressions or waivers.

## Evidence required

- `factory architecture health --json` must report `decision: HEALTHY`.
- The consolidated audit tests and architecture-health tests must pass.
- Ruff lint and format checks for the changed Python test modules must pass.
- Exact line and normalized-byte sizes are bound by `architecture-policy.json`.
- Each future use of this reserve requires an ADR naming the files, recording
  before/after measurements, and carrying passing relevant tests plus
  specialty-agent review; the next growth beyond these ceilings blocks CI.

## Consequences

- The current 0.47.0 candidate can be evaluated without silently raising the
  cap or suppressing the Python-file metric.
- The Python inventory has at most five files of reserve, and the five adjusted
  modules have at most five percent of measured file-size reserve.
- Growth beyond that reserve blocks CI and requires consolidation or a
  separately reviewed decision with new evidence.
- Release cadence, protected CI, specialist-agent review, and publisher checks
  remain independent release gates.
