# Plan: commercial-packaging-v1

Spec: `specs/commercial-packaging-v1.md`

Architect verdict: PASS

## Atomic tasks

- [x] T1 | slice=specs | files=specs/commercial-packaging-v1.md,specs/commercial-packaging-v1.ssat.yaml | verify=`specline strict commercial-packaging-v1 --root .` | Define the no-sales, human-controlled packaging contract.
- [x] T2 | slice=docs | files=docs/COMMERCIAL_PACKAGING.md,docs/COMMERCIAL_PACKAGING.json | verify=`py -3.11 -m pytest -q tests/test_commercial_packaging.py` | Publish a machine-readable and human-readable free/Team/Enterprise boundary.
- [x] T3 | slice=.github | files=.github/ISSUE_TEMPLATE/design-partner.yml | verify=`py -3.11 -m pytest -q tests/test_commercial_packaging.py` | Prepare a high-level, non-secret design-partner intake form without acceptance authority.
- [x] T4 | slice=README.md | files=README.md | verify=`py -3.11 -m pytest -q tests/test_commercial_packaging.py tests/test_publication_metadata.py` | Link concise commercial context without turning the README into a pricing page.
- [x] T5 | slice=docs | files=docs/OVERVIEW.md,docs/ENTERPRISE_TEAMS_OPERATIONS.md | verify=`py -3.11 -m pytest -q tests/test_commercial_packaging.py` | Link precise availability context from the operational documentation.
- [x] T6 | slice=tests | files=tests/test_commercial_packaging.py | verify=`py -3.11 -m pytest -q tests/test_commercial_packaging.py` | Bind availability, proposed-price, and no-authority claims to deterministic tests.

## Release boundary

- [x] T7 | slice=factoryline | files=factoryline/enterprise_enforcement.py,factoryline/enterprise_ops.py,factoryline/enterprise_receipts.py,factoryline/cli_enterprise.py | verify=`py -3.11 -m pytest -q tests/test_commercial_packaging.py` | Consolidate inactive policy, native usage locking, DSSE verification and lazy CLI without authority expansion.
- [x] T8 | slice=factoryline | files=factoryline/cli.py,factoryline/runtime_audit.py | verify=`py -3.11 -m pytest -q tests/test_commercial_packaging.py` | Rewire existing entry points without changing behavior.
- [x] T9 | slice=tests | files=tests/test_commercial_packaging.py | verify=`py -3.11 -m pytest -q tests/test_commercial_packaging.py` | Preserve every commercial test, parameter and native concurrency control in the canonical suite.
- [x] T10 | slice=docs | files=docs/COMMERCIAL_PACKAGING.md,docs/commercial-model.md | verify=`py -3.11 -m pytest -q tests/test_commercial_packaging.py` | Merge the duplicate implementation guide without activating a service.
- [x] T11 | slice=factoryline | files=factoryline/commercial_policy.py,factoryline/commercial_usage.py,factoryline/commercial_entitlement.py | verify=`py -3.11 -m pytest -q tests/test_commercial_packaging.py` | Delete the three duplicate policy, ledger and entitlement implementations after rewiring.
- [x] T12 | slice=factoryline | files=factoryline/commercial_gate.py,factoryline/cli_commercial.py | verify=`py -3.11 -m pytest -q tests/test_commercial_packaging.py` | Delete duplicate admission and CLI implementations after rewiring.
- [x] T13 | slice=tests | files=tests/test_commercial_policy.py,tests/test_commercial_usage.py,tests/test_commercial_entitlement.py,tests/test_commercial_gate.py | verify=`py -3.11 -m pytest -q tests/test_commercial_packaging.py` | Delete duplicate test files only after preserving every test in the canonical suite.
- [x] T14 | slice=factoryline | files=factoryline/enterprise_enforcement.py,factoryline/enterprise_ops.py,factoryline/cli_enterprise.py,factoryline/enterprise_receipts.py | verify=`py -3.11 -m ruff check --select C901 factoryline/enterprise_enforcement.py factoryline/enterprise_ops.py factoryline/cli_enterprise.py factoryline/enterprise_receipts.py` | Extract cohesive commercial admission, policy, replay, reservation, entitlement and CLI helpers preserving all behavior and the existing Ruff and ForgeLine AST complexity maximum of 10; retain actual repo-wide quality and attribution artifacts.
- [x] T15 | slice=factoryline | files=factoryline/enterprise_receipts.py | verify=`py -3.11 -m pytest -q tests/test_deep_audit.py::test_worker_images_ship_entrypoint_import_closure_and_detect_omissions` | Preserve minimal worker SDK import closure with lazy commercial storage resolution, without expanding worker image copy lists.

- [x] T16 | slice=tests | files=tests/test_commercial_packaging.py | verify=`py -3.11 -m pytest -q tests/test_commercial_packaging.py` | Add direct public-API execution checks for configuration, policy limits, ledger views, entitlement payload validation and commercial CLI plan/usage JSON; preserve every prior test body and assert positive and negative boundaries.

This plan prepares source-controlled public copy and an optional inbound issue
template only. It does not publish a release, open an issue, enable checkout,
change Marketplace pricing, accept a customer, or create a commercial contract.
