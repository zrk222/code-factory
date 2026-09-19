# Code Factory 0.46.7 — Cross-platform audit coverage restored

## Why this patch matters

The security audit must be equally strict on Windows and Linux. A workspace
under `/tmp` was previously mistaken for an ignored temporary subtree, which
could make a scan inspect no Python files and incorrectly report `CLEAN`.

## What changed

- Security source discovery now applies ignore rules to workspace-relative
  paths, never absolute parent directories.
- Linux CI now exercises the same dynamic-execution, syntax-error, and
  concurrent-mutation fail-closed checks as local Windows runs.
- The release carries the already verified deterministic drift detector and
  the VS Code 0.9.9 adapter metadata.

## Evidence boundary

This release reports deterministic local/static findings and receipts. It does
not claim a general security certification or grant merge, publication, or
deployment authority.
