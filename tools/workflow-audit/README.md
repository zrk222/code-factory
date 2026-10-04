# Universal workflow evidence gate

`python -m factoryline.cli audit workflows --root <project> --contract <relative-contract.json> --observations <relative-observations.json> --json`

This source command evaluates any project's declared checks and profiles. It
reuses Journey Proof containment, canonical hashing and explicit false authority.
It does not run an application or convert recorded labels into certification.

Global routing contract: `C:/Users/rkatz/.codex/routers/workflow-qa.md`.
Every coding change must declare happy path, validation, failure/recovery, state,
security/privacy, performance, accessibility and external effects applicability.
Only relevant categories require execution, with explicit review of exclusions.
PASS/N/A require evidence and execution identity; N/A cannot waive an applicable
check. Candidate and catalog drift, missing/duplicate/unknown profiles, FAIL,
BLOCKED and stale/escaping files prevent a green receipt.

Tests use CLI, API and mobile fixture projects to verify the validator. They do
not establish workflow behavior of a real deployed product. The currently
installed PyPI CLI remains unchanged; use this source entry until a separate
verified package release installs the command.
