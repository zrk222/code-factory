# ADR: Keep the tracked Python source ceiling at 460

Status: accepted by repository owner request, 2026-10-05

## Decision

Set the repository architecture budget and Code Factory security scanner source
inventory limit to 460 Python files. Keep the existing hard-fail behavior when
the scanner discovers more than 460 eligible Python files; do not raise the cap
to accommodate growth. The paired AppForge, RevenueForge, and Prestige benchmark
runner lives in the existing benchmark test module to avoid adding a Python file.

## Rationale

The user explicitly required a strict 460-file limit while preserving the
quality grade target. The current tracked candidate had 461 Python files because
the benchmark runner was added as a new source file. Moving that runner into the
existing benchmark test module preserves reproducible measurements without
expanding the Python file inventory.

## Verification

Acceptance requires exactly 460 or fewer tracked Python files, a blocked scan
when the declared scanner limit is exceeded, strict architecture health, and a
ForgeLine composite grade of at least 97.9 without changing grade weights.
