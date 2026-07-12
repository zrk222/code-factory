# Plan: control-plane-foundation

Spec: specs/control-plane.md

## Tasks

- [x] T1 | slice=specs | files=specs/control-plane.md | verify=`python -m pytest -q tests/test_control_plane.py::test_contract_document_is_present` | Define tenant, authorization, approval, and audit invariants
- [x] T2 | slice=factoryline | files=factoryline/control_plane.py | verify=`python -m pytest -q tests/test_control_plane.py` | Implement local evidence store, tenant authorization, approvals, and audit chain
- [x] T3 | slice=cli | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_control_plane.py::test_cli_control_plane_round_trip` | Expose deterministic control-plane commands without network access
- [x] T4 | slice=tests | files=tests/test_control_plane.py | verify=`python -m pytest -q tests/test_control_plane.py` | Add boundary, denial, approval, and tamper tests
- [x] T5 | slice=docs | files=docs/CONTROL_PLANE.md,README.md | verify=`python -m pytest -q` | Document exact scope and the hosted-adapter boundary

## Scope boundary

This plan does not implement SSO/SCIM, webhook authentication, a hosted API, or
provider-specific SCM apps. It provides the deterministic authorization and
evidence contract those adapters must call.
