# Plan: native-database-context
Spec: specs/native-database-context.md (approved before implementation)
Architect verdict: PASS

## Tasks (atomic � each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/intent_quality.py | verify=`ruff check factoryline/intent_quality.py` | Build bounded immutable SQL/ORM database graph extraction with source provenance, explicit gaps and content-identity reuse.
- [ ] T2 | slice=factoryline | files=factoryline/review_audits.py,factoryline/audit_action_refs.py,factoryline/mission_control_status.py | verify=`ruff check factoryline/review_audits.py factoryline/audit_action_refs.py factoryline/mission_control_status.py` | Integrate native database context and fresh SQL source bindings into existing sealed scan receipts and their consumers with lazy parser loading and unchanged file ceilings.
- [ ] T3 | slice=tests | files=tests/test_review_integrity.py,tests/test_context_efficiency.py | verify=`python -m pytest -q tests/test_review_integrity.py -k database_context` | Prove SQL dialect, quoted identifiers, ORM aliases, joins, unsupported forms, resource bounds, negative controls, hash determinism and stale-source behavior.
- [ ] T4 | slice=factoryline | files=factoryline/context_efficiency.py | verify=`ruff check factoryline/context_efficiency.py` | Expose affected entities, dependent queries and evidence gaps through existing context packets for CF, ForgeLine and SpecLine.
- [ ] T5 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m pip check` | Declare one lazy SQL AST parser dependency for native database analysis.
- [ ] T6 | slice=CHANGELOG.md | files=CHANGELOG.md | verify=`git diff --check` | Describe the native static database context and its explicit evidence boundaries.

## Regression ledger

Dependency evidence: `rg -n 'database_structure|database_workspace_context|verify_database_context|_security_scan_state' factoryline tests -g '*.py'`.

| Changed module | Downstream consumers | Acceptance command |
| --- | --- | --- |
| `intent_quality` database reader | `context_efficiency`, `review_audits` | `python -m pytest -q tests/test_review_integrity.py -k database_context` |
| `context_efficiency` database capture | `review_audits`, selected context packets | `python -m pytest -q tests/test_context_efficiency.py -k database` |
| `audit_action_refs` scan verdict | `review_audits` scan and runtime evidence paths | `python -m pytest -q tests/test_review_integrity.py -k incomplete_audit_coverage` |
| `review_audits` oracle projection | existing oracle-cache callers | `python -m pytest -q tests/test_review_audits.py -k test_oracle_context_cache_invalidates_when_projector_helper_changes` |

Propagation: rerun affected checks after observable changes; reuse recorded passes
when their source dependency closure is unchanged. Keep the first failure and its
correction evidence. Disable unrelated global pytest plugin autoload for these
local commands. SQLGlot must be available from the declared package environment;
the private development parser target is not a production import path. These
commands establish the selected local behavior, not full product or release approval.
