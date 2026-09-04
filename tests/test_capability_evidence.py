from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from factoryline.capability_evidence import CapabilityEvidenceError, audit_capability_evidence
from factoryline.cli import main


def _manifest(root: Path, test_body: str = "assert True\n") -> Path:
    (root / "implementation.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "test_claim.py").write_text("def test_claim():\n" + textwrap.indent(test_body, "    "), encoding="utf-8")
    path = root / "claims.json"
    path.write_text(json.dumps({"schema": "factory.capability-evidence-manifest.v1", "capabilities": [{"id": "claim", "maturity": "controlled_pilot", "implementation": ["implementation.py"], "tests": ["test_claim.py"], "verify": {"argv": ["python", "-m", "pytest", "-q", "test_claim.py"], "timeout_seconds": 10}}]}), encoding="utf-8")
    return path


def test_structural_audit_hashes_files_without_execution_or_inflated_claim(tmp_path: Path):
    _manifest(tmp_path)
    result = audit_capability_evidence(tmp_path, Path("claims.json"))
    assert result["marker"] == "CAPABILITY_EVIDENCE_BOUND"
    assert result["execution_count"] == 0
    assert len(result["claims"][0]["implementation"][0]["sha256"]) == 64
    assert "not independent battle-testing" in result["claim_boundary"]
    assert all(value is False for value in result["authority"].values())


def test_explicit_execution_reports_verified_only_for_zero_exit(tmp_path: Path):
    _manifest(tmp_path)
    result = audit_capability_evidence(tmp_path, Path("claims.json"), execute=True)
    assert result["marker"] == "CAPABILITY_EVIDENCE_VERIFIED"
    assert result["execution_count"] == 1
    assert result["executions"][0]["passed"] is True


@pytest.mark.parametrize(("path", "code"), [("../outside.py", "E_CAPABILITY_EVIDENCE_PATH"), ("missing.py", "E_CAPABILITY_EVIDENCE_MISSING")])
def test_detached_evidence_fails_closed(tmp_path: Path, path: str, code: str):
    manifest = _manifest(tmp_path)
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["capabilities"][0]["tests"] = [path]
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(CapabilityEvidenceError) as caught:
        audit_capability_evidence(tmp_path, Path("claims.json"))
    assert caught.value.code == code


def test_empty_evidence_fails_closed(tmp_path: Path):
    _manifest(tmp_path)
    (tmp_path / "test_claim.py").write_bytes(b"")
    with pytest.raises(CapabilityEvidenceError) as caught:
        audit_capability_evidence(tmp_path, Path("claims.json"))
    assert caught.value.code == "E_CAPABILITY_EVIDENCE_HOLLOW"


def test_nonzero_verification_is_blocked(tmp_path: Path):
    _manifest(tmp_path, "assert False\n")
    result = audit_capability_evidence(tmp_path, Path("claims.json"), execute=True)
    assert result["marker"] == "CAPABILITY_EVIDENCE_BLOCKED"
    assert result["ok"] is False
    assert result["executions"][0]["returncode"] == 1


def test_evidence_changed_during_verification_is_blocked(tmp_path: Path):
    _manifest(tmp_path, "from pathlib import Path\nPath('implementation.py').write_text('VALUE = 2\\n')\n")
    result = audit_capability_evidence(tmp_path, Path("claims.json"), execute=True)
    assert result["marker"] == "CAPABILITY_EVIDENCE_BLOCKED"
    assert result["executions"][0]["evidence_changed"] is True


def test_whole_manifest_is_validated_before_any_command_runs(tmp_path: Path, monkeypatch):
    manifest = _manifest(tmp_path)
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    invalid = dict(raw["capabilities"][0], id="later", tests=["missing.py"])
    raw["capabilities"].append(invalid)
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setattr("factoryline.capability_evidence.run_bounded_command", lambda *args, **kwargs: pytest.fail("command ran before validation completed"))
    with pytest.raises(CapabilityEvidenceError) as caught:
        audit_capability_evidence(tmp_path, Path("claims.json"), execute=True)
    assert caught.value.code == "E_CAPABILITY_EVIDENCE_MISSING"


def test_cli_returns_stable_json_and_nonzero_for_failed_execution(tmp_path: Path, capsys):
    _manifest(tmp_path, "assert False\n")
    code = main(["evidence-audit", "claims.json", "--root", str(tmp_path), "--execute", "--json"])
    result = json.loads(capsys.readouterr().out)
    assert code == 1
    assert result["marker"] == "CAPABILITY_EVIDENCE_BLOCKED"


def test_repository_manifest_binds_all_public_maturity_classes():
    root = Path(__file__).parents[1]
    result = audit_capability_evidence(root, Path("evidence/capability-evidence.json"))
    assert {item["maturity"] for item in result["claims"]} == {"locally_verified_core", "controlled_pilot", "reference_pilot", "candidate_bound_preflight"}


def test_oversized_verifier_output_is_bounded_and_blocks(tmp_path: Path):
    _manifest(tmp_path, "print('x' * 9000000)\nassert False\n")
    result = audit_capability_evidence(tmp_path, Path("claims.json"), execute=True)
    execution = result["executions"][0]
    assert result["marker"] == "CAPABILITY_EVIDENCE_BLOCKED"
    assert execution["output_limit_exceeded"] is True
    assert execution["stdout_bytes"] > 8 * 1024 * 1024
    assert "x" * 100 not in json.dumps(execution)


def test_timeout_kills_descendant_that_inherits_streams(tmp_path: Path):
    manifest = _manifest(
        tmp_path,
        "import subprocess, sys, time\nsubprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\ntime.sleep(30)\n",
    )
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["capabilities"][0]["verify"]["timeout_seconds"] = 1
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    started = __import__("time").monotonic()
    result = audit_capability_evidence(tmp_path, Path("claims.json"), execute=True)
    execution = result["executions"][0]
    assert execution["timed_out"] is True
    assert execution["cleanup_confirmed"] is True
    assert __import__("time").monotonic() - started < 10
