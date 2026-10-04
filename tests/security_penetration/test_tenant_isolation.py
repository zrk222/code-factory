from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.audit_trace import build_audit_trace, verify_audit_trace
from factoryline.control_plane import ControlPlaneError, EvidenceStore, Principal


_REPO = Path(__file__).resolve().parents[2]
_TEST_PATH = "tests/security_penetration/test_tenant_isolation.py"
_SOURCE_PATHS = [
    "factoryline/audit_trace.py",
    "factoryline/control_plane.py",
    _TEST_PATH,
]


def _evidence(tenant: str) -> dict[str, str]:
    return {
        "schema": "factory.receipt.v2",
        "tenant_id": tenant,
        "subject_digest": "a" * 64,
        "policy_sha256": "b" * 64,
        "verdict": "VERIFIED",
        "stage": "compile",
    }


def _input_ref(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_cross_tenant_role_operation_matrix_is_denied_and_traced(
    tmp_path: Path, record_property: pytest.FixtureRequest
) -> None:
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    tenant_a = Principal("owner-a", "tenant-a", ("operator",))
    tenant_b_operator = Principal("owner-b", "tenant-b", ("operator",))
    evidence_a = store.put(tenant_a, _evidence("tenant-a"), evidence_id="a-record")
    evidence_b = store.put(tenant_b_operator, _evidence("tenant-b"), evidence_id="b-record")
    request = store.request_approval(tenant_a, "tenant-a", evidence_a["evidence_id"], "boundary matrix")
    rows: list[tuple[str, str, str]] = []

    for role in ("viewer", "operator", "approver"):
        principal = Principal(f"{role}-b", "tenant-b", (role,))
        attempts = {
            "read": lambda: store.get(principal, "tenant-a", evidence_a["evidence_id"]),
            "list": lambda: store.list(principal, "tenant-a"),
            "write": lambda: store.put(
                principal, _evidence("tenant-a"), evidence_id=f"cross-{role}"
            ),
            "approval_decide": lambda: store.decide_approval(
                principal, "tenant-a", request["approval_id"], "approved", "cross-tenant attempt"
            ),
        }
        for operation, attempt in attempts.items():
            with pytest.raises(ControlPlaneError) as denied:
                attempt()
            assert denied.value.code in {"E_TENANT_BOUNDARY", "E_ACTION_DENIED"}
            rows.append((role, operation, denied.value.code))

    assert len(rows) == 12
    assert [item["evidence_id"] for item in store.list(tenant_a, "tenant-a")] == [
        evidence_a["evidence_id"]
    ]
    assert [item["evidence_id"] for item in store.list(tenant_b_operator, "tenant-b")] == [
        evidence_b["evidence_id"]
    ]
    assert store.get_approval(
        Principal("approver-a", "tenant-a", ("approver",)),
        "tenant-a",
        request["approval_id"],
    )["status"] == "pending"

    trace = build_audit_trace(
        _REPO,
        changed_paths=_SOURCE_PATHS,
        lane_states={
            "authorization_tenant_isolation": "PASS",
        },
        steps=[
            {
                "step_id": f"{role}-{operation}",
                "input": _input_ref(f"{role}:{operation}:{code}"),
                "guard": "TENANT_ROLE_AUTHORIZATION",
                "decision": "DENY_CROSS_TENANT",
                "state": "PASS",
                "source_paths": ["factoryline/control_plane.py", _TEST_PATH],
            }
            for role, operation, code in rows
        ],
    )
    assert verify_audit_trace(trace) == {"valid": True, "errors": []}
    assert len(trace["steps"]) == 12
    assert all("tenant" not in step["input"] for step in trace["steps"])
    record_property("factoryline_audit_trace_id", trace["trace_id"])
    record_property("factoryline_audit_trace", json.dumps(trace, sort_keys=True))
