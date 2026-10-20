# Capability evidence map

Code Factory asks you not to trust an agent's story. Apply the same rule to
Code Factory. This page separates executable local evidence from product
maturity so a green test is never presented as independent production proof.

| Surface | Maturity | What is executable now | Inspect and rerun | What is not claimed |
|---|---|---|---|---|
| `factory scan` | Locally verified core | Zero-config relative inventory in the fast path, with an opt-in bounded Python static scan; emits a blocked or explicitly incomplete first verdict | `factory scan --root . --json` or `factory scan --root . --deep --json` | No runtime, dependency, tenant-scope, or release certification; a clean static result remains incomplete without project evidence |
| `factory first-proof` | Locally verified core | Runs a disposable positive/negative demonstration and records a bounded inventory of the selected workspace | `python -m pytest -q tests/test_adoption.py tests/test_e2e_proof.py tests/test_adoption_guide.py` | The demo does not execute or certify your repository; inventory, usage scale, and defect-reduction impact are not inferred |
| Oracle Firewall + `factory wrap` | Controlled pilot | Binds supplied intent and admission artifacts, observes an admitted local command, challenges validator behavior, and records bounded evidence | `python -m pytest -q tests/test_oracle_firewall.py tests/test_evidence_supply_line.py tests/test_continuity.py::test_contract_document_is_present tests/test_continuity.py::test_tenant_scoped_evidence_round_trip tests/test_continuity.py::test_cross_tenant_read_and_write_are_denied_before_access tests/test_continuity.py::test_unknown_role_is_denied tests/test_continuity.py::test_repair_execute_grant_is_limited_to_operator_and_admin tests/test_continuity.py::test_approval_requires_distinct_approver_and_records_reason tests/test_continuity.py::test_cross_tenant_approval_is_denied tests/test_continuity.py::test_audit_tampering_is_detected_without_cross_tenant_leak tests/test_continuity.py::test_cli_control_plane_round_trip tests/test_continuity.py::test_rest_adapter_requires_identity_and_supports_approval_flow tests/test_continuity.py::test_workflow_approval_verifier_survives_restart_and_exact_retry tests/test_continuity.py::test_workflow_repair_dispatch_requires_authenticated_requester tests/test_continuity.py::test_workflow_approval_requires_approved_decision tests/test_continuity.py::test_workflow_approval_rejects_expired_or_invalid_expiry tests/test_continuity.py::test_workflow_approval_rejects_different_binding tests/test_continuity.py::test_workflow_approval_rechecks_current_identity_and_role tests/test_continuity.py::test_workflow_approval_rejects_cross_tenant_and_missing_resolver tests/test_continuity.py::test_workflow_approval_corrupt_evidence_is_not_consumed tests/test_continuity.py::test_workflow_approval_concurrent_retry_records_one_consumption tests/test_continuity.py::test_workflow_approval_failed_audit_rolls_back_consumption tests/test_continuity.py::test_workflow_approval_rejects_reused_fingerprint_and_revoked_role tests/test_continuity.py::test_workflow_approval_changed_during_identity_resolution_is_fenced` | No universal sandbox, external agent identity proof, automatic approval, or production rollout claim |
| Enterprise enforcement reference | Reference pilot | Exercises local policy, replay, expiry, scope, receipt, and read-only Graph Ops contracts | `python -m pytest -q tests/test_enterprise_enforcement.py tests/test_graph_ops.py` | No hosted multi-tenant service, SLA, certification, customer reference, or procurement-readiness claim |
| AppForge | Candidate-bound preflight | Checks supplied build-bound policy, metadata, media, design, privacy, and release evidence and emits visible blockers | `python -m pytest -q tests/test_appforge*.py` | No real-device result unless imported as evidence; no upload, TestFlight delivery, store review, or approval guarantee |

## How to evaluate it fairly

Hollow-test detection is only one audit lane. [Implementation audits](CODE_REVIEW_AUDITS.md)
add peer-pattern comparison and bounded guard-path bypass analysis to `factory change review`.
Run `python -m pytest -q tests/test_review_audits.py tests/test_change_review.py` to challenge these implementations.
Their scope is declared Python symbols; structural findings are not whole-program or runtime security proof.

The machine-readable claim manifest lives in `evidence/capability-evidence.json`.
From a repository checkout, inspect its file bindings without running code:

```powershell
factory evidence-audit --json
```

After reviewing its declared commands, execute those local checks:

```powershell
factory evidence-audit --execute --json
```

The default result is `CAPABILITY_EVIDENCE_BOUND`, not a passing test claim.
Only explicit execution with every command returning zero produces
`CAPABILITY_EVIDENCE_VERIFIED`. Missing, empty, escaping, or failing evidence
blocks the audit. Returned file hashes bind the report to the inspected bytes.
Execution runs repository code as your user; it is not a sandbox or an
independent assessment. Neither result authorizes publication or deployment.

1. Run `factory scan --root .` for the current repository, then use
   `factory first-proof --root .` in a throwaway workspace to verify the
   sandbox proof path.
2. Read the named test and implementation before trusting the receipt.
3. Introduce a known-bad case and confirm the relevant test fails. The
   repository's ForgeLine smoke gates use this same stub-mutation principle.
4. Pilot one team workflow with a named human owner, exact scope, and explicit
   stop condition before connecting it to a consequential pipeline.
5. Treat external scale, operational reliability, productivity, and adoption
   as unknown until independent observations exist.

The repository suite proves the checked behavior under its fixtures. It does
not prove that every feature is independently battle-tested, that every
integration is production infrastructure, or that an outside reviewer will
agree with a local judgment. Those claims remain withheld by design.
