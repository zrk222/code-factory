# Universal workflow audit plan
Plan review: PASS (specialty AI Engineer review, 2026-10-02; design only). Implementation status: COMPLETE locally; publication and package integration remain separate.
Architect verdict: PASS (specialty AI Engineer review, 2026-10-02; design only).
- [x] T1 | slice=factoryline | files=factoryline/workflow_audit.py,factoryline/cli_audit.py | verify=`python -m pytest -q tests/test_workflow_audit.py tests/test_review_audits.py` | BIND COVERAGE EVIDENCE PATH AUTHORITY
- [x] T2 | slice=tests | files=tests/test_workflow_audit.py | verify=`python -m pytest -q tests/test_workflow_audit.py` | neutral CLI/API fixtures, omission, duplicates, unknown refs, malformed JSON types, resource budgets, tamper, containment and stable machine-readable output
- [x] T3 | slice=.factory | files=.factory/workflow-audit-contract.json,.factory/workflow-audit-observations.json | verify=`python -m factoryline.cli audit workflows --root . --contract .factory/workflow-audit-contract.json --observations .factory/workflow-audit-observations.json --json` | bind final checks and inspect every recorded artifact before completion
