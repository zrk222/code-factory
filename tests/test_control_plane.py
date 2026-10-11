from __future__ import annotations

import json
from io import BytesIO
import sqlite3
from pathlib import Path

import pytest

from factoryline.control_plane import (
    ControlPlaneError,
    EvidenceStore,
    Principal,
)
from factoryline.cli import main
from factoryline.control_api import ControlPlaneAPI


def _operator(tenant: str = "tenant-a", subject: str = "operator") -> Principal:
    return Principal(subject=subject, tenant_id=tenant, roles=("operator",))


def _approver(tenant: str = "tenant-a", subject: str = "approver") -> Principal:
    return Principal(subject=subject, tenant_id=tenant, roles=("approver",))


def _admin(tenant: str = "tenant-a", subject: str = "admin") -> Principal:
    return Principal(subject=subject, tenant_id=tenant, roles=("admin",))


def _evidence(tenant: str = "tenant-a") -> dict:
    return {
        "schema": "factory.receipt.v2",
        "tenant_id": tenant,
        "subject_digest": "a" * 64,
        "policy_sha256": "b" * 64,
        "verdict": "VERIFIED",
        "stage": "compile",
    }


def test_contract_document_is_present():
    path = Path("specs/control-plane.md")
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "tenant boundary" in text
    assert "hash-link" in text


def test_tenant_scoped_evidence_round_trip(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    record = store.put(_operator(), _evidence(), evidence_id="e-1")
    assert record["evidence_id"] == "e-1"
    assert record["payload_sha256"]
    assert store.get(_operator(), "tenant-a", "e-1")["payload"]["verdict"] == "VERIFIED"
    assert len(store.list(_operator(), "tenant-a")) == 1
    assert store.verify_audit(_operator(), "tenant-a")["valid"] is True


def test_cross_tenant_read_and_write_are_denied_before_access(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    store.put(_operator(), _evidence(), evidence_id="e-1")
    with pytest.raises(ControlPlaneError, match="another tenant") as read_error:
        store.get(_operator(), "tenant-b", "e-1")
    assert read_error.value.code == "E_TENANT_BOUNDARY"
    with pytest.raises(ControlPlaneError) as write_error:
        store.put(_operator(), _evidence("tenant-b"), evidence_id="e-2")
    assert write_error.value.code == "E_TENANT_BOUNDARY"
    assert store.list(_operator(), "tenant-a")[0]["evidence_id"] == "e-1"


def test_unknown_role_is_denied(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    with pytest.raises(ControlPlaneError) as error:
        store.put(Principal("guest", "tenant-a", ("unknown",)), _evidence())
    assert error.value.code == "E_ACTION_DENIED"


def test_approval_requires_distinct_approver_and_records_reason(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    request = store.request_approval(
        _admin(),
        "tenant-a",
        store.put(_admin(), _evidence())["evidence_id"],
        "release candidate",
    )
    with pytest.raises(ControlPlaneError) as self_error:
        store.decide_approval(
            _admin(), "tenant-a", request["approval_id"], "approved", "I approve"
        )
    assert self_error.value.code == "E_SELF_APPROVAL"
    decided = store.decide_approval(
        _approver(),
        "tenant-a",
        request["approval_id"],
        "approved",
        "independent review complete",
    )
    assert decided["status"] == "approved"
    assert decided["approver"] == "approver"
    assert decided["decision_reason"] == "independent review complete"
    with pytest.raises(ControlPlaneError) as second_error:
        store.decide_approval(
            _approver("tenant-a", "second-approver"),
            "tenant-a",
            request["approval_id"],
            "rejected",
            "too late",
        )
    assert second_error.value.code == "E_ALREADY_DECIDED"


def test_cross_tenant_approval_is_denied(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    evidence_id = store.put(_operator(), _evidence())["evidence_id"]
    request = store.request_approval(_operator(), "tenant-a", evidence_id, "review")
    with pytest.raises(ControlPlaneError) as error:
        store.decide_approval(
            _approver("tenant-b", "other"),
            "tenant-a",
            request["approval_id"],
            "approved",
            "bad",
        )
    assert error.value.code == "E_TENANT_BOUNDARY"


def test_audit_tampering_is_detected_without_cross_tenant_leak(tmp_path):
    db_path = tmp_path / "evidence.sqlite3"
    store = EvidenceStore(db_path)
    store.put(_operator(), _evidence(), evidence_id="e-1")
    store.put(_operator("tenant-b", "other"), _evidence("tenant-b"), evidence_id="e-2")
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE audit_events SET payload_json = ? WHERE tenant_id = ?",
            (json.dumps({"changed": True}), "tenant-a"),
        )
        db.commit()
    result = store.verify_audit(_operator(), "tenant-a")
    assert result["valid"] is False
    assert result["events"] == 1
    assert all("tenant-b" not in error for error in result["errors"])


def test_cli_control_plane_round_trip(tmp_path, capsys):
    db = tmp_path / "control.sqlite3"
    payload = tmp_path / "receipt.json"
    payload.write_text(json.dumps(_evidence()), encoding="utf-8")
    assert main(["control", "init", "--db", str(db)]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "control",
                "evidence-put",
                str(payload),
                "--db",
                str(db),
                "--tenant",
                "tenant-a",
                "--subject",
                "ci",
                "--roles",
                "operator",
            ]
        )
        == 0
    )
    evidence = json.loads(capsys.readouterr().out)
    assert evidence["tenant_id"] == "tenant-a"
    assert (
        main(
            [
                "control",
                "audit-verify",
                "--db",
                str(db),
                "--tenant",
                "tenant-a",
                "--subject",
                "audit",
                "--roles",
                "viewer",
            ]
        )
        == 0
    )
    audit = json.loads(capsys.readouterr().out)
    assert audit["valid"] is True


def _api_call(app, method, path, *, body=None, subject=None, tenant=None, roles=None):
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    data = json.dumps(body).encode("utf-8") if body is not None else b""
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(data)),
        "wsgi.input": BytesIO(data),
    }
    if subject is not None:
        environ["HTTP_X_FACTORY_SUBJECT"] = subject
    if tenant is not None:
        environ["HTTP_X_FACTORY_TENANT"] = tenant
    if roles is not None:
        environ["HTTP_X_FACTORY_ROLES"] = roles
    result = b"".join(app(environ, start_response))
    return captured["status"], json.loads(result)


def test_rest_adapter_requires_identity_and_supports_approval_flow(tmp_path):
    app = ControlPlaneAPI(tmp_path / "api.sqlite3")
    status, health = _api_call(app, "GET", "/healthz")
    assert status == "200 OK" and health["ok"] is True
    status, denied = _api_call(app, "GET", "/v1/evidence")
    assert status == "400 Bad Request"
    assert denied["error"]["code"] == "E_IDENTITY_REQUIRED"
    status, evidence = _api_call(
        app,
        "POST",
        "/v1/evidence",
        body=_evidence(),
        subject="ci",
        tenant="tenant-a",
        roles="operator",
    )
    assert status == "201 Created"
    evidence_id = evidence["evidence_id"]
    status, request = _api_call(
        app,
        "POST",
        f"/v1/evidence/approvals/{evidence_id}",
        body={"reason": "release review"},
        subject="ci",
        tenant="tenant-a",
        roles="operator",
    )
    assert status == "201 Created"
    status, decided = _api_call(
        app,
        "POST",
        f"/v1/evidence/approvals/{request['approval_id']}/decision",
        body={"decision": "approved", "reason": "independent review"},
        subject="release-manager",
        tenant="tenant-a",
        roles="approver",
    )
    assert status == "200 OK" and decided["status"] == "approved"
    status, audit = _api_call(
        app, "GET", "/v1/audit", subject="audit", tenant="tenant-a", roles="viewer"
    )
    assert status == "200 OK" and audit["valid"] is True


def workflow_approval_setup(
    tmp_path, *, decision="approved", expires_at="2099-01-01T00:00:00+00:00"
):
    expected = dict(
        source_sha256="a" * 64,
        run_id="run-1",
        phase="planning",
        kind="approved_plan",
        artifact_sha256="b" * 64,
        verifier_id="approval-host",
    )
    store = EvidenceStore(tmp_path / "approvals.sqlite3")
    record = store.put(
        _operator(),
        dict(
            schema="factory.workflow-approval.v1",
            tenant_id="tenant-a",
            expires_at=expires_at,
            phase_evidence=expected,
        ),
    )
    approval = store.request_approval(
        _operator(), "tenant-a", record["evidence_id"], "Review bound plan"
    )
    if decision != "pending":
        store.decide_approval(
            _approver(),
            "tenant-a",
            approval["approval_id"],
            decision,
            "Independent review",
        )
    return store, approval["approval_id"], expected


def test_workflow_approval_verifier_survives_restart_and_exact_retry(tmp_path):
    store, approval_id, expected = workflow_approval_setup(tmp_path)

    def resolver(subject, tenant):
        return _approver(tenant, subject)

    verifier = EvidenceStore(store.path).workflow_approval_verifier(
        _operator(), "tenant-a", approval_id, resolve_principal=resolver
    )
    assert verifier(expected) == expected
    assert verifier(expected) == expected
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute("SELECT count(*) FROM workflow_approval_uses").fetchone()[0] == 1
        )
        assert (
            db.execute(
                "SELECT count(*) FROM audit_events WHERE action='approval.workflow.consume'"
            ).fetchone()[0]
            == 1
        )
    assert store.verify_audit(_operator(), "tenant-a")["valid"]


@pytest.mark.parametrize("decision", ["pending", "rejected"])
def test_workflow_approval_requires_approved_decision(tmp_path, decision):
    store, approval_id, expected = workflow_approval_setup(tmp_path, decision=decision)
    verifier = store.workflow_approval_verifier(
        _operator(),
        "tenant-a",
        approval_id,
        resolve_principal=lambda s, t: _approver(t, s),
    )
    with pytest.raises(ControlPlaneError) as caught:
        verifier(expected)
    assert caught.value.code == "E_APPROVAL_REQUIRED"


@pytest.mark.parametrize(
    "expiry", ["2000-01-01T00:00:00+00:00", "2099-01-01", "invalid"]
)
def test_workflow_approval_rejects_expired_or_invalid_expiry(tmp_path, expiry):
    store, approval_id, expected = workflow_approval_setup(tmp_path, expires_at=expiry)
    verifier = store.workflow_approval_verifier(
        _operator(),
        "tenant-a",
        approval_id,
        resolve_principal=lambda s, t: _approver(t, s),
    )
    with pytest.raises(ControlPlaneError) as caught:
        verifier(expected)
    assert caught.value.code == "E_APPROVAL_EVIDENCE"


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_sha256", "c" * 64),
        ("run_id", "other-run"),
        ("artifact_sha256", "d" * 64),
        ("phase", "building"),
    ],
)
def test_workflow_approval_rejects_different_binding(tmp_path, field, value):
    store, approval_id, expected = workflow_approval_setup(tmp_path)
    verifier = store.workflow_approval_verifier(
        _operator(),
        "tenant-a",
        approval_id,
        resolve_principal=lambda s, t: _approver(t, s),
    )
    with pytest.raises(ControlPlaneError):
        verifier({**expected, field: value})
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute("SELECT count(*) FROM workflow_approval_uses").fetchone()[0] == 0
        )


@pytest.mark.parametrize(
    "resolver",
    [
        lambda s, t: _operator(t, s),
        lambda s, t: _approver(t, "imposter"),
        lambda s, t: _approver("tenant-b", s),
        lambda s, t: None,
    ],
)
def test_workflow_approval_rechecks_current_identity_and_role(tmp_path, resolver):
    store, approval_id, expected = workflow_approval_setup(tmp_path)
    verifier = store.workflow_approval_verifier(
        _operator(), "tenant-a", approval_id, resolve_principal=resolver
    )
    with pytest.raises(ControlPlaneError):
        verifier(expected)


def test_workflow_approval_rejects_cross_tenant_and_missing_resolver(tmp_path):
    store, approval_id, expected = workflow_approval_setup(tmp_path)
    with pytest.raises(ControlPlaneError):
        store.workflow_approval_verifier(
            _operator(),
            "tenant-b",
            approval_id,
            resolve_principal=lambda s, t: _approver(t, s),
        )
    with pytest.raises(ControlPlaneError):
        store.workflow_approval_verifier(
            _operator(), "tenant-a", approval_id, resolve_principal=None
        )


def test_workflow_approval_corrupt_evidence_is_not_consumed(tmp_path):
    store, approval_id, expected = workflow_approval_setup(tmp_path)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE evidence SET payload_json='null'")
    verifier = store.workflow_approval_verifier(
        _operator(),
        "tenant-a",
        approval_id,
        resolve_principal=lambda s, t: _approver(t, s),
    )
    with pytest.raises(ControlPlaneError) as caught:
        verifier(expected)
    assert caught.value.code == "E_APPROVAL_EVIDENCE"


def test_workflow_approval_concurrent_retry_records_one_consumption(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    store, approval_id, expected = workflow_approval_setup(tmp_path)

    def consume():
        reopened = EvidenceStore(store.path)
        verify = reopened.workflow_approval_verifier(
            _operator(),
            "tenant-a",
            approval_id,
            resolve_principal=lambda s, t: _approver(t, s),
        )
        return verify(expected)

    with ThreadPoolExecutor(max_workers=2) as workers:
        assert list(workers.map(lambda _: consume(), range(2))) == [expected, expected]
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute("SELECT count(*) FROM workflow_approval_uses").fetchone()[0] == 1
        )
        assert (
            db.execute(
                "SELECT count(*) FROM audit_events WHERE action='approval.workflow.consume'"
            ).fetchone()[0]
            == 1
        )


def test_workflow_approval_failed_audit_rolls_back_consumption(tmp_path, monkeypatch):
    store, approval_id, expected = workflow_approval_setup(tmp_path)
    original = store._audit

    def fail(*args, **kwargs):
        raise RuntimeError("interruption")

    monkeypatch.setattr(store, "_audit", fail)
    verify = store.workflow_approval_verifier(
        _operator(),
        "tenant-a",
        approval_id,
        resolve_principal=lambda s, t: _approver(t, s),
    )
    with pytest.raises(RuntimeError, match="interruption"):
        verify(expected)
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute("SELECT count(*) FROM workflow_approval_uses").fetchone()[0] == 0
        )
    monkeypatch.setattr(store, "_audit", original)
    assert verify(expected) == expected


def test_workflow_approval_rejects_reused_fingerprint_and_revoked_role(tmp_path):
    store, approval_id, expected = workflow_approval_setup(tmp_path)
    verify = store.workflow_approval_verifier(
        _operator(),
        "tenant-a",
        approval_id,
        resolve_principal=lambda s, t: _approver(t, s),
    )
    assert verify(expected) == expected
    revoked = store.workflow_approval_verifier(
        _operator(),
        "tenant-a",
        approval_id,
        resolve_principal=lambda s, t: _operator(t, s),
    )
    with pytest.raises(ControlPlaneError) as caught:
        revoked(expected)
    assert caught.value.code == "E_ACTION_DENIED"
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE workflow_approval_uses SET fingerprint=?", ("c" * 64,))
    with pytest.raises(ControlPlaneError) as caught:
        verify(expected)
    assert caught.value.code == "E_APPROVAL_REPLAY"


def test_workflow_approval_changed_during_identity_resolution_is_fenced(tmp_path):
    store, approval_id, expected = workflow_approval_setup(tmp_path)

    def resolve(subject, tenant):
        with sqlite3.connect(store.path) as db:
            db.execute(
                "UPDATE approvals SET status='rejected' WHERE approval_id=?",
                (approval_id,),
            )
        return _approver(tenant, subject)

    verify = store.workflow_approval_verifier(
        _operator(), "tenant-a", approval_id, resolve_principal=resolve
    )
    with pytest.raises(ControlPlaneError) as caught:
        verify(expected)
    assert caught.value.code == "E_APPROVAL_CHANGED"
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute("SELECT count(*) FROM workflow_approval_uses").fetchone()[0] == 0
        )
