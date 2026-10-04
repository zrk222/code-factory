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
six-file budget adjustment to admit the named, reviewed audit surfaces. It
does not grant additional headroom: any further Python file growth blocks until
another explicit architecture decision. Other architecture budgets, module
file-size guards, and CI checks remain enforced. The gate continues measuring
the repository inventory without suppressions or waivers.

## Evidence required

- `factory architecture health --json` must report `decision: HEALTHY`.
- The consolidated audit tests and architecture-health tests must pass.
- Ruff lint and format checks for the changed Python test modules must pass.

## Consequences

- The current 0.47.0 candidate can be evaluated without silently raising the
  cap or suppressing the Python-file metric.
- The repository has no remaining Python-file growth allowance; future module
  additions require consolidation or a separately reviewed decision.
- Release cadence, protected CI, specialist-agent review, and publisher checks
  remain independent release gates.
