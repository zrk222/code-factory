from pathlib import Path
import json

from factoryline.ide_playbook import ide_playbook
from factoryline.mcp import dispatch
from factoryline.mission_control_status import (
    mission_control_status,
    prepare_security_scan_receipt_report,
    security_scan_status,
    security_scan_pytest_collection_snapshot,
    write_security_scan_receipt,
)


def _complete_security_scan_receipt(root: Path, *, body="pass"):
    from factoryline.review_audits import _seal_security_scan, security_scan

    before_collection = security_scan_pytest_collection_snapshot(root)
    (root / ".factory").mkdir(exist_ok=True)
    contract = root / ".factory" / "tenant-read-contract.json"
    contract.write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    (root / "test_case.py").write_text(
        f"def test_hollow():\n    {body}\n", encoding="utf-8"
    )
    report = security_scan(root)
    report["tenant_read_contract"]["configuration"] = {
        "path": ".factory/tenant-read-contract.json",
        "sha256": __import__("hashlib").sha256(contract.read_bytes()).hexdigest(),
        "bytes": contract.stat().st_size,
        "state": "loaded",
    }
    report = _seal_security_scan(report)
    report = prepare_security_scan_receipt_report(root, report, before_collection)
    return write_security_scan_receipt(root, report)


def test_runtime_assurance_is_visible_to_agents_humans_and_mcp(tmp_path: Path):
    playbook = ide_playbook()
    pack = next(
        item
        for item in playbook["capability_packs"]
        if item["id"] == "runtime_assurance"
    )
    assert pack["next"] == "factory.runtime_audit_status"
    mission = mission_control_status(tmp_path)
    assert mission["evidence"]["runtime_assurance"]["state"] == "NOT_RUN"
    inventory = dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, tmp_path)
    assert "factory.runtime_audit_status" in [
        item["name"] for item in inventory["result"]["tools"]
    ]
    call = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "factory.runtime_audit_status"},
        },
        tmp_path,
    )
    assert call["result"]["content"][0]["text"].find("RUNTIME_AUDIT_MCP_READ_ONLY") >= 0


def test_graph_ops_ui_shows_six_lanes_and_actionable_output():
    html = Path("factoryline/graph_ops.html").read_text(encoding="utf-8")
    assert "RUNTIME_ASSURANCE_SIX_LANES" in html
    for label in (
        "Stateful workflows",
        "Tenant isolation",
        "Failure recovery",
        "Consumer compatibility",
        "Migration integrity",
        "Performance + memory",
    ):
        assert label in html
    assert "Next repair:" in html


def test_completed_runtime_assurance_routes_to_named_human_review(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setattr(
        "factoryline.mission_control_status.runtime_audit_status",
        lambda _root: {"state": "READY_FOR_HUMAN_REVIEW"},
    )
    mission = mission_control_status(tmp_path)
    assert mission["state"] == "review_required"
    assert mission["human_control_plane"]["review_required"] is True


def test_security_scan_receipt_is_current_hash_bound_and_advisory(tmp_path: Path):
    receipt = _complete_security_scan_receipt(tmp_path)

    status = security_scan_status(tmp_path)
    mission = mission_control_status(tmp_path)
    audit = mission["evidence"]["implementation_audit"]

    assert receipt["receipt_sha256"] == status["receipt_sha256"]
    assert status["state"] == "FINDINGS"
    assert status["candidate_freshness"] == "CURRENT_SOURCE_HASHES_VERIFIED"
    assert status["authority"]["execution"] is False
    assert status["verification"] == "local_self_hash_only_not_signature_or_approval"
    assert any(item["code"] == "QUALITY_HOLLOW_TEST" for item in status["findings"])
    probe = next(
        item["native_assertion_probe"]
        for item in status["findings"]
        if item.get("native_assertion_probe")
    )
    assert probe["available"] is False
    assert audit["receipt_sha256"] == status["receipt_sha256"]

    (tmp_path / "test_case.py").write_text(
        "def test_hollow():\n    changed_operation()\n", encoding="utf-8"
    )
    stale = security_scan_status(tmp_path)
    assert stale["state"] == "INCOMPLETE"
    assert stale["candidate_freshness"] == "SOURCE_HASH_MISMATCH"
    assert any(item["code"] == "QUALITY_HOLLOW_TEST" for item in stale["findings"])


def test_security_scan_source_removed_after_receipt_is_incomplete(tmp_path: Path):
    _complete_security_scan_receipt(tmp_path)
    (tmp_path / "test_case.py").unlink()

    status = security_scan_status(tmp_path)

    assert status["state"] == "INCOMPLETE"
    assert status["candidate_freshness"] == "SOURCE_INVENTORY_MISMATCH"
    assert status["incomplete"] is True


def test_security_scan_receipt_rejects_finding_count_mismatch(tmp_path: Path):
    from factoryline.deep_audit_io import canonical_bytes, digest
    from factoryline.review_audits import _seal_security_scan

    _complete_security_scan_receipt(tmp_path)
    receipt_path = tmp_path / ".factory" / "security-scan" / "latest.json"
    envelope = json.loads(receipt_path.read_text(encoding="utf-8"))
    envelope["report"]["finding_counts"] = {}
    envelope["report"] = _seal_security_scan(envelope["report"])
    unsigned = {
        key: value for key, value in envelope.items() if key != "receipt_sha256"
    }
    envelope["receipt_sha256"] = digest(unsigned)
    receipt_path.write_bytes(canonical_bytes(envelope))

    status = security_scan_status(tmp_path)

    assert status["state"] == "INVALID"
    assert status["reason"] == "finding count mismatch"


def test_security_scan_receipt_rejects_clean_state_with_findings(tmp_path: Path):
    from factoryline.deep_audit_io import canonical_bytes, digest
    from factoryline.review_audits import _seal_security_scan

    _complete_security_scan_receipt(tmp_path)
    receipt_path = tmp_path / ".factory" / "security-scan" / "latest.json"
    envelope = json.loads(receipt_path.read_text(encoding="utf-8"))
    envelope["report"]["state"] = "CLEAN"
    envelope["report"] = _seal_security_scan(envelope["report"])
    unsigned = {
        key: value for key, value in envelope.items() if key != "receipt_sha256"
    }
    envelope["receipt_sha256"] = digest(unsigned)
    receipt_path.write_bytes(canonical_bytes(envelope))

    status = security_scan_status(tmp_path)

    assert status["state"] == "INVALID"
    assert status["reason"] == "clean scan contains findings"


def test_security_scan_receipt_detects_new_higher_priority_pytest_config(
    tmp_path: Path,
):
    from factoryline.review_audits import _seal_security_scan, security_scan

    (tmp_path / ".factory").mkdir()
    contract = tmp_path / ".factory" / "tenant-read-contract.json"
    contract.write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n", encoding="utf-8"
    )
    (tmp_path / "test_case.py").write_text(
        "def test_hollow():\n    pass\n", encoding="utf-8"
    )
    before_collection = security_scan_pytest_collection_snapshot(tmp_path)
    report = security_scan(tmp_path)
    report["tenant_read_contract"]["configuration"] = {
        "path": ".factory/tenant-read-contract.json",
        "sha256": __import__("hashlib").sha256(contract.read_bytes()).hexdigest(),
        "bytes": contract.stat().st_size,
        "state": "loaded",
    }
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\npython_files = test_*.py\n", encoding="utf-8"
    )
    report = prepare_security_scan_receipt_report(
        tmp_path, _seal_security_scan(report), before_collection
    )
    write_security_scan_receipt(tmp_path, report)

    status = security_scan_status(tmp_path)

    assert before_collection["path"] == "pyproject.toml"
    assert status["state"] == "INCOMPLETE"
    assert status["report_state"] == "INCOMPLETE"
    assert status["candidate_freshness"] == "PYTEST_COLLECTION_CHANGED_DURING_SCAN"
    assert any(item["code"] == "QUALITY_HOLLOW_TEST" for item in status["findings"])


def test_security_scan_receipt_missing_invalid_and_incomplete_are_never_clean(
    tmp_path: Path,
):
    assert security_scan_status(tmp_path)["state"] == "NOT_RUN"

    receipt_path = tmp_path / ".factory" / "security-scan" / "latest.json"
    receipt_path.parent.mkdir(parents=True)
    receipt_path.write_text("{not-json", encoding="utf-8")
    assert security_scan_status(tmp_path)["state"] == "INVALID"

    receipt_path.unlink()
    _complete_security_scan_receipt(tmp_path)
    envelope = json.loads(receipt_path.read_text(encoding="utf-8"))
    envelope["report"]["audit_coverage"]["complete"] = False
    from factoryline.deep_audit_io import canonical_bytes, digest

    from factoryline.review_audits import _seal_security_scan

    envelope["report"] = _seal_security_scan(envelope["report"])
    unsigned = {
        key: value for key, value in envelope.items() if key != "receipt_sha256"
    }
    envelope["receipt_sha256"] = digest(unsigned)
    receipt_path.write_bytes(canonical_bytes(envelope))
    incomplete = security_scan_status(tmp_path)
    assert incomplete["state"] == "INCOMPLETE"
    assert incomplete["incomplete"] is True
    assert incomplete["output_truncated"] is False


def test_security_scan_projection_bounds_findings_and_probe_advice(tmp_path: Path):
    from factoryline.review_audits import _seal_security_scan, security_scan

    before_collection = security_scan_pytest_collection_snapshot(tmp_path)
    (tmp_path / ".factory").mkdir()
    contract = tmp_path / ".factory" / "tenant-read-contract.json"
    contract.write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    tests = "\n".join(f"def test_hollow_{i}():\n    operation_{i}()" for i in range(28))
    (tmp_path / "test_cases.py").write_text(tests + "\n", encoding="utf-8")
    report = security_scan(tmp_path)
    report["tenant_read_contract"]["configuration"] = {
        "path": ".factory/tenant-read-contract.json",
        "sha256": __import__("hashlib").sha256(contract.read_bytes()).hexdigest(),
        "bytes": contract.stat().st_size,
        "state": "loaded",
    }
    report = prepare_security_scan_receipt_report(
        tmp_path, _seal_security_scan(report), before_collection
    )
    write_security_scan_receipt(tmp_path, report)

    status = security_scan_status(tmp_path)
    assert status["finding_count"] == 28
    assert len(status["findings"]) == 24
    assert status["display_truncated"] is True
    assert status["findings_truncated"] is True
    assert status["findings"][0]["native_assertion_probe"]["call_available"] is True


def test_security_scan_receipt_is_visible_in_graph_ops_ui_without_html_injection():
    html = Path("factoryline/graph_ops.html").read_text(encoding="utf-8")

    assert 'id="security-scan-panel"' in html
    assert 'id="security-scan-findings"' in html
    assert "renderSecurityScanReceipt(payload)" in html
    start = html.index("function renderSecurityScanReceipt(payload)")
    end = html.index("function renderAuditResults(payload)", start)
    renderer = html[start:end]
    assert "addText(" in renderer
    assert "innerHTML" not in renderer
    assert "native_assertion_probe" in renderer
    assert "output_truncated" in renderer
    assert "display_truncated" in renderer
    assert "security-scan-detail" in renderer


def test_security_scan_cli_writes_receipt_consumed_by_mission_control(
    tmp_path: Path, capsys
):
    from factoryline.cli import main

    factory = tmp_path / ".factory"
    factory.mkdir()
    (factory / "tenant-read-contract.json").write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "def test_addition():\n    assert 1 + 1 == 2\n", encoding="utf-8"
    )

    exit_code = main(["audit", "security", "--root", str(tmp_path), "--json"])
    capsys.readouterr()

    receipt = tmp_path / ".factory" / "security-scan" / "latest.json"
    assert exit_code in {0, 1}
    assert receipt.is_file()
    status = security_scan_status(tmp_path)
    assert status["state"] in {"CLEAN", "FINDINGS"}
    assert status["candidate_freshness"] == "CURRENT_SOURCE_HASHES_VERIFIED"


def test_security_scan_cli_write_failure_is_bounded_and_does_not_leak_path(
    tmp_path: Path, monkeypatch, capsys
):
    from factoryline.cli import main

    factory = tmp_path / ".factory"
    factory.mkdir()
    (factory / "tenant-read-contract.json").write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "def test_addition():\n    assert 1 + 1 == 2\n", encoding="utf-8"
    )

    def fail_write(_root, _report):
        raise OSError(f"permission denied: {tmp_path / 'private-host-path'}")

    monkeypatch.setattr(
        "factoryline.mission_control_status.write_security_scan_receipt", fail_write
    )
    exit_code = main(["audit", "security", "--root", str(tmp_path), "--json"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert '"state": "INVALID"' in captured.err
    assert str(tmp_path) not in captured.err
    assert "private-host-path" not in captured.err


def test_security_scan_receipt_preserves_undefined_call_incompleteness(tmp_path):
    # Receipt transport cannot upgrade a source-unknown invocation into HOLLOW.
    _complete_security_scan_receipt(tmp_path, body="operation()")
    status = security_scan_status(tmp_path)
    assert status["state"] == "INCOMPLETE"
    assert status["candidate_freshness"] == "CURRENT_SOURCE_HASHES_VERIFIED"
    assert any(
        item["code"] == "QUALITY_UNKNOWN_TEST_ORACLE" for item in status["findings"]
    )
    assert not any(item["code"] == "QUALITY_HOLLOW_TEST" for item in status["findings"])
