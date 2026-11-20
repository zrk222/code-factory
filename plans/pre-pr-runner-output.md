# Plan: pre-pr-runner-output
Spec: specs/pre-pr-runner-output.md
Architect verdict: APPROVED_BY_OWNER_2026_11_19
Owner said "Approve architecture; implement and test"; root recorded proposal SHA256 7e6acdc03763af9018c21c93402367442b5c6ad5726db259a1c3a9b29c77537e. Historical agent-generated approval receipts are preserved and do not substitute for this owner decision.
## Logical decomposition (phases)
1. Closed declaration and bounded runner capture.
2. Host verification and existing proof admission.
3. Actual CLI lifecycle and negative controls.
## Tasks (atomic)
- [ ] T1 | slice=factoryline | files=factoryline/senior_assurance.py,factoryline/live_feedback.py | verify=`py -3.11 -m pytest tests/test_senior_assurance.py -q` | Validate 1 through 16 report paths and aggregate captured bytes within declared max_output_bytes (1 through 1048576); capture actual runner reports before deletion, propagate final cleanup-confirmed evidence, and never export failed/planned/cancelled or cleanup-unconfirmed results.
- [ ] T2 | slice=factoryline | files=factoryline/incremental_scheduler.py | verify=`py -3.11 -m pytest tests/test_change_review.py -q` | Reject inter-gate output overlap and every input/oracle/intent/authority/manifest/contract binding overlap before dispatch, including protected paths under .factory/reports/; independently validate payload before host export and existing proof admission.
- [ ] T3 | slice=tests | files=tests/test_change_review.py,tests/test_senior_assurance.py | verify=`py -3.11 -m pytest tests/test_change_review.py tests/test_senior_assurance.py -q` | Exercise actual CLI and bounded subprocess controls for generated/rewritten output, exact reuse, tamper, missing/linked/escaping files, ownership/protected overlap, count/aggregate-byte limits and failed/planned/cancelled/cleanup-failed execution; preserve existing source/oracle/release checks. No new test module.

## Approval and remaining gates
- Owner reviews .factory/pre-pr-runner-output/architecture-decision.md before any ForgeLine architecture transition or further production repair.
- Only after explicit architecture approval: forge gate architected pre-pr-runner-output --root .; then forge architect pre-pr-runner-output specs/pre-pr-runner-output.ssat.yaml --root . --adopt-existing. Do not force overwrite the partial implementation.
- After authorized implementation: strict SpecLine validator challenges, non-hollow ForgeLine verify-tests/smoke, scoped and repository QA, relevant complete suites and hash-bound workflow audit. Historical six-case XML is not current full acceptance.
