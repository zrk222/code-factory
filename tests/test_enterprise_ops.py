from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import sys

import pytest

from factoryline.enterprise_ops import (
    EnterpriseOpsError,
    _execute_runner,
    evaluate_required_checks,
    evaluate_sla,
    export_evidence,
    export_otel,
    initialize_workspace,
    outcome_summary,
    provision_identity,
    put_evidence,
    record_outcome,
    run_proof,
    verify_workspace,
    workspace_status,
)


def _init(tmp_path: Path) -> Path:
    initialize_workspace(tmp_path, "acme", "owner@example.com")
    return tmp_path


def test_workspace_identity_and_evidence_are_tenant_bound(tmp_path: Path):
    root = _init(tmp_path)
    provision_identity(
        root, "acme", "operator@example.com", "operator", actor="owner@example.com"
    )
    evidence = put_evidence(
        root,
        "acme",
        "operator@example.com",
        {"schema": "factory.test.v1", "tenant_id": "acme", "verdict": "PASS"},
    )
    assert evidence["marker"] == "EVIDENCE_RECORDED"
    assert evidence["eops_marker"] == "EOPS_EVIDENCE_READY"
    assert verify_workspace(root)["eops_marker"] == "EOPS_EVIDENCE_READY"
    assert verify_workspace(root)["valid"] is True
    with pytest.raises(EnterpriseOpsError, match="tenant"):
        put_evidence(
            root,
            "other",
            "operator@example.com",
            {"schema": "factory.test.v1", "tenant_id": "other"},
        )


def test_suspended_identity_is_denied_before_mutation(tmp_path: Path):
    root = _init(tmp_path)
    provision_identity(
        root,
        "acme",
        "operator@example.com",
        "operator",
        actor="owner@example.com",
        status="suspended",
    )
    with pytest.raises(EnterpriseOpsError) as error:
        put_evidence(
            root,
            "acme",
            "operator@example.com",
            {"schema": "factory.test.v1", "tenant_id": "acme"},
        )
    assert error.value.code == "E_IDENTITY_INACTIVE"
    assert verify_workspace(root)["evidence"] == 0


def test_evidence_tamper_is_detected(tmp_path: Path):
    root = _init(tmp_path)
    put_evidence(
        root,
        "acme",
        "owner@example.com",
        {"schema": "factory.test.v1", "tenant_id": "acme", "verdict": "PASS"},
    )
    db = root / ".factory" / "ops" / "evidence.db"
    import sqlite3

    with sqlite3.connect(db) as connection:
        connection.execute(
            "UPDATE evidence SET payload_json = ?",
            ('{"schema":"factory.test.v1","tenant_id":"acme","verdict":"FAIL"}',),
        )
    result = verify_workspace(root)
    assert result["marker"] == "OPS_WORKSPACE_TAMPERED"
    assert any("payload hash mismatch" in item for item in result["errors"])


def test_process_runner_requires_explicit_boundary_and_is_labelled(tmp_path: Path):
    root = _init(tmp_path)
    with pytest.raises(EnterpriseOpsError) as error:
        run_proof(root, [sys.executable, "-c", "print('ok')"], backend="process")
    assert error.value.code == "E_RUNNER_ISOLATION_REQUIRED"
    receipt = run_proof(
        root,
        [
            sys.executable,
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr)",
        ],
        backend="process",
        allow_process_boundary=True,
    )
    assert receipt["marker"] == "RUNNER_NOT_ISOLATED"
    assert receipt["eops_marker"] == "EOPS_RUNNER_READY"
    assert receipt["status"] == "passed"
    assert receipt["authority"]["deploy"] is False
    assert receipt["output"] == f"out{os.linesep}\nerr{os.linesep}"
    assert receipt["output_complete"] is True
    stdout = f"out{os.linesep}".encode()
    stderr = f"err{os.linesep}".encode()
    assert receipt["process_facts"]["stdout_bytes"] == len(stdout)
    assert receipt["process_facts"]["stderr_bytes"] == len(stderr)
    assert (
        receipt["process_facts"]["stdout_sha256"] == hashlib.sha256(stdout).hexdigest()
    )
    assert (
        receipt["process_facts"]["stderr_sha256"] == hashlib.sha256(stderr).hexdigest()
    )
    assert receipt["process_facts"]["cleanup_confirmed"] is True
    assert receipt["process_facts"]["capture_cleanup_confirmed"] is True
    assert receipt["process_facts"]["capture_limit_bytes_per_stream"] == 8 * 1024 * 1024
    assert receipt["container_cleanup"] == "NOT_APPLICABLE"


def test_docker_unavailable_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    root = _init(tmp_path)
    monkeypatch.setattr("factoryline.enterprise_ops.shutil.which", lambda name: None)
    with pytest.raises(EnterpriseOpsError) as error:
        run_proof(root, ["python", "-c", "print('ok')"], backend="docker")
    assert error.value.code == "E_RUNNER_BACKEND_UNAVAILABLE"


@pytest.mark.parametrize("length,status", [(1024, "passed"), (1025, "incomplete")])
def test_proof_runner_truncated_output_cannot_pass(
    tmp_path, monkeypatch, length, status
):
    root = _init(tmp_path)
    monkeypatch.setattr(
        "factoryline.enterprise_ops._execute_runner",
        lambda *args: {
            "facts": {
                "exit_code": 0,
                "timed_out": False,
                "launch_error": False,
                "output_limit_exceeded": False,
                "cleanup_confirmed": True,
            },
            "stdout": "x" * length,
            "stderr": "",
            "capture_cleanup_confirmed": True,
            "capture_read_complete": True,
        },
    )
    receipt = run_proof(
        root,
        ["python", "-c", "pass"],
        backend="process",
        allow_process_boundary=True,
        output_limit=1024,
    )
    assert receipt["status"] == status
    assert receipt["output_truncated"] is (length > 1024)
    assert receipt["output_complete"] is (length <= 1024)


def test_process_runner_output_overflow_is_bounded_and_incomplete(tmp_path: Path):
    root = _init(tmp_path)
    command = (
        "import sys; chunk=b'x'*65536; "
        "[sys.stdout.buffer.write(chunk) for _ in range(129)]"
    )
    receipt = run_proof(
        root,
        [sys.executable, "-c", command],
        backend="process",
        allow_process_boundary=True,
        timeout_seconds=30,
    )
    facts = receipt["process_facts"]
    assert receipt["status"] == "incomplete"
    assert facts["output_limit_exceeded"] is True
    assert facts["stdout_bytes"] > facts["capture_limit_bytes_per_stream"]
    assert len(facts["stdout_sha256"]) == 64
    if not facts["cleanup_confirmed"]:
        print("process_facts=" + json.dumps(facts, sort_keys=True))
    assert facts["cleanup_confirmed"] is True, facts
    assert facts["capture_cleanup_confirmed"] is True
    assert receipt["output_complete"] is False
    assert not list((root / ".factory" / "ops").glob(".proof-capture-*"))


def test_reader_join_uses_one_cleanup_deadline_and_preserves_unknown_cleanup(
    monkeypatch,
):
    import factoryline.runtime_audit_process as runtime_process

    class Reader:
        def __init__(self, finishes_at):
            self.finishes_at = finishes_at
            self.join_timeouts = []

        def join(self, timeout):
            self.join_timeouts.append(timeout)
            if clock[0] < self.finishes_at:
                clock[0] = min(self.finishes_at, clock[0] + timeout)

        def is_alive(self):
            return clock[0] < self.finishes_at

    clock = [0.0]
    monkeypatch.setattr(runtime_process.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(runtime_process.time, "sleep", lambda duration: None)
    monkeypatch.setattr(
        runtime_process.assembly_process, "CLEANUP_TIMEOUT_SECONDS", 10.0
    )
    cleanup_calls = []
    monkeypatch.setattr(
        runtime_process, "_stop", lambda child: cleanup_calls.append(child) or True
    )
    child = object()
    readers = [Reader(5.0), Reader(11.0)]

    cleanup, closed = runtime_process._join_stream_readers(child, readers, False)

    assert cleanup is False
    assert closed is False
    assert cleanup_calls == [child]
    assert readers[0].join_timeouts == [10.0, 0.0]
    assert readers[1].join_timeouts == [5.0, 0.0]

    clock[0] = 0.0
    ready_readers = [Reader(2.0), Reader(4.0)]
    cleanup, closed = runtime_process._join_stream_readers(child, ready_readers, True)
    assert cleanup is True
    assert closed is True
    assert cleanup_calls == [child]


def test_process_runner_timeout_is_not_a_pass(tmp_path: Path):
    root = _init(tmp_path)
    receipt = run_proof(
        root,
        [
            sys.executable,
            "-c",
            "import time; print('started', flush=True); time.sleep(10)",
        ],
        backend="process",
        allow_process_boundary=True,
        timeout_seconds=1,
    )
    assert receipt["status"] == "timeout"
    assert receipt["process_facts"]["timed_out"] is True
    assert receipt["process_facts"]["cleanup_confirmed"] is True
    assert receipt["output"].startswith("started")
    assert receipt["output_complete"] is False


@pytest.mark.parametrize(
    "fact_changes,cleanup,read_complete,expected",
    [
        ({"output_limit_exceeded": True}, True, True, "incomplete"),
        ({"output_limit_exceeded": True, "exit_code": 120}, True, True, "incomplete"),
        ({"cleanup_confirmed": False}, True, True, "incomplete"),
        ({}, False, True, "incomplete"),
        ({}, True, False, "incomplete"),
    ],
)
def test_runner_terminal_facts_gate_green_status(
    tmp_path, monkeypatch, fact_changes, cleanup, read_complete, expected
):
    root = _init(tmp_path)
    facts = {
        "exit_code": 0,
        "timed_out": False,
        "launch_error": False,
        "output_limit_exceeded": False,
        "cleanup_confirmed": True,
    }
    facts.update(fact_changes)
    monkeypatch.setattr(
        "factoryline.enterprise_ops._execute_runner",
        lambda *args: {
            "facts": facts,
            "stdout": "ok\n",
            "stderr": "",
            "capture_cleanup_confirmed": cleanup,
            "capture_read_complete": read_complete,
        },
    )
    receipt = run_proof(
        root,
        [sys.executable, "-c", "pass"],
        backend="process",
        allow_process_boundary=True,
    )
    assert receipt["status"] == expected


def test_aborted_docker_cli_does_not_claim_container_cleanup(tmp_path, monkeypatch):
    root = _init(tmp_path)
    monkeypatch.setattr(
        "factoryline.enterprise_ops._runner_argv",
        lambda *args: (
            ["docker", "run", "--rm", "image", "command"],
            {"backend": "docker", "isolation": "container"},
        ),
    )
    monkeypatch.setattr(
        "factoryline.enterprise_ops._execute_runner",
        lambda *args: {
            "facts": {
                "exit_code": 0,
                "timed_out": True,
                "launch_error": False,
                "output_limit_exceeded": False,
                "cleanup_confirmed": True,
            },
            "stdout": "",
            "stderr": "",
            "capture_cleanup_confirmed": True,
            "capture_read_complete": True,
        },
    )
    receipt = run_proof(
        root,
        ["command"],
        backend="docker",
        timeout_seconds=1,
    )
    assert receipt["status"] == "timeout"
    assert receipt["container_cleanup"] == "NOT_INDEPENDENTLY_VERIFIED"


def test_spawn_error_does_not_disclose_absolute_path(tmp_path: Path):
    root = _init(tmp_path)
    missing = tmp_path / "missing-proof-executable.exe"
    with pytest.raises(EnterpriseOpsError) as error:
        run_proof(
            root,
            [str(missing)],
            backend="process",
            allow_process_boundary=True,
        )
    assert error.value.code == "E_RUNNER_EXECUTION"
    assert str(tmp_path) not in str(error.value)


def test_runner_rejects_capture_root_symlink_before_creating_outside(
    tmp_path: Path,
):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    try:
        (workspace / ".factory").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    with pytest.raises(EnterpriseOpsError) as error:
        _execute_runner([sys.executable, "-c", "pass"], workspace, 1)

    assert error.value.code == "E_RUNNER_CAPTURE"
    assert not (outside / "ops").exists()


def test_required_checks_reject_truncated_passed_receipt(tmp_path):
    root = _init(tmp_path)
    (root / "src.py").write_text("value = 1\n")
    receipt = root / "proof.json"
    receipt.write_text(
        json.dumps(
            {
                "status": "passed",
                "output_truncated": True,
                "changed_paths": ["src.py"],
            }
        )
    )
    result = evaluate_required_checks(root, ["src.py"], proof_receipts=["proof.json"])
    assert result["decision"] == "REVIEW_REQUIRED"
    assert result["missing"] == ["src.py"]


def test_required_checks_report_missing_and_ready(tmp_path: Path):
    root = _init(tmp_path)
    changed = root / "src.py"
    changed.write_text("print('x')", encoding="utf-8")
    missing = evaluate_required_checks(root, ["src.py"])
    assert missing["decision"] == "REVIEW_REQUIRED"
    assert missing["eops_marker"] == "EOPS_CHECK_READY"
    receipt = root / "receipt.json"
    receipt.write_text(
        json.dumps(
            {
                "verified": True,
                "changed_paths": ["src.py"],
                "created_at": "2999-01-01T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    ready = evaluate_required_checks(root, ["src.py"], proof_receipts=[str(receipt)])
    assert ready["decision"] == "READY_FOR_HUMAN_REVIEW"
    assert ready["authority"]["merge"] is False


def test_outcomes_are_hash_linked_and_otel_export_is_metadata_only(tmp_path: Path):
    root = _init(tmp_path)
    record_outcome(
        root,
        "acme",
        "owner@example.com",
        service="api",
        environment="prod",
        result="deployed",
        duration_ms=42,
        deployed=True,
    )
    record_outcome(
        root,
        "acme",
        "owner@example.com",
        service="api",
        environment="prod",
        result="rolled_back",
        duration_ms=12,
        rollback=True,
    )
    summary = outcome_summary(root)
    assert summary["integrity"]["valid"] is True
    assert summary["deployments"] == 1
    assert summary["rollbacks"] == 1
    assert (
        record_outcome(
            root,
            "acme",
            "owner@example.com",
            service="api",
            environment="prod",
            result="success",
            duration_ms=1,
        )["eops_marker"]
        == "EOPS_OUTCOME_READY"
    )
    exported = export_otel(root, root / "otel.json")
    assert exported["events"] == 3
    assert "prompts" in exported["disclosure"]


def test_sla_requires_all_seven_explicit_gates(tmp_path: Path):
    root = _init(tmp_path)
    proposed = evaluate_sla(root)
    assert proposed["status"] == "PROPOSED"
    assert proposed["eops_marker"] == "EOPS_SLA_READY"
    assert len(proposed["missing_gates"]) == 7
    manifest = {
        "gates": {
            name: {"verified": True, "evidence": f"receipt-{name}"}
            for name in proposed["gates"]
        }
    }
    manifest["gates"]["signed_acceptance"]["signature_sha256"] = "a" * 64
    path = tmp_path / "sla.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    ready = evaluate_sla(root, path)
    assert ready["status"] == "READY_FOR_CONTRACT"
    assert ready["active"] is False


def test_export_and_status_keep_authority_explicit(tmp_path: Path):
    root = _init(tmp_path)
    output = export_evidence(root, tmp_path / "evidence-export.json")
    assert output["marker"] == "OPS_EXPORT_WRITTEN"
    status = workspace_status(root)
    assert status["marker"] == "OPS_STATUS_READY"
    assert status["eops_marker"] == "EOPS_GOLDEN_READY"
    assert set(status["markers"]) == {
        "EOPS_EVIDENCE_READY",
        "EOPS_IDENTITY_READY",
        "EOPS_RUNNER_READY",
        "EOPS_CHECK_READY",
        "EOPS_OUTCOME_READY",
        "EOPS_SLA_READY",
        "EOPS_GOLDEN_READY",
    }
    assert status["checks"]["decision"] == "NOT_EVALUATED"
    assert status["authority"]["merge"] is False
    assert status["authority"]["sla_activation"] is False
