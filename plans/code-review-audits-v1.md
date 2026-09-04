# Plan: code-review-audits-v1
Spec: specs/code-review-audits-v1.md
Architect verdict: PASS

## Tasks
- [x] T1 | slice=factoryline | files=factoryline/review_audits.py | verify=`python -m pytest -q tests/test_review_audits.py` | Implement bounded peer-pattern and guard-path audits with source bindings.
- [x] T2 | slice=factoryline | files=factoryline/change_review.py,factoryline/cli.py,factoryline/github_proof_review.py | verify=`python -m pytest -q tests/test_review_audits.py tests/test_change_review.py` | Integrate CLI and change-review lanes without granting authority.
- [x] T3 | slice=tests | files=tests/test_review_audits.py | verify=`python -m pytest -q tests/test_review_audits.py` | Challenge bypasses, unsupported syntax, tampering, and actual CLI integration.
- [x] T4 | slice=docs | files=docs/CODE_REVIEW_AUDITS.md | verify=`python -m pytest -q tests/test_review_audits.py` | Provide exact policy example, commands, limitations and user outcomes.
