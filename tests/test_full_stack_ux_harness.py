from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.full_stack_ux_harness import (
    CORE_CHECKS,
    JUDGMENTS,
    UI_CHECKS,
    FullStackUXHarnessError,
    quality_harness_template,
    verify_quality_harness,
)
from factoryline.optimizer import optimize_pr


def _write_manifest(root: Path, *, ui: bool = True) -> Path:
    evidence = root / "native-checks.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    manifest = quality_harness_template(ui_in_scope=ui)
    for check in manifest["checks"]:
        check.update(state="passed", provenance="trusted_source", evidence=[evidence.name])
    manifest["reviewer"] = {"name": "Release Owner", "type": "human"}
    for judgment in manifest["judgments"]:
        judgment.update(approved=True, rationale=f"Reviewed {judgment['id']} against the stated user task and evidence.")
    path = root / "quality.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_template_has_closed_core_ui_and_judgment_sets():
    ui = quality_harness_template(ui_in_scope=True)
    non_ui = quality_harness_template(ui_in_scope=False)
    assert [item["id"] for item in ui["checks"]] == [*CORE_CHECKS, *UI_CHECKS]
    assert [item["id"] for item in non_ui["checks"]] == list(CORE_CHECKS)
    assert [item["id"] for item in ui["judgments"]] == list(JUDGMENTS)
    assert all(item["state"] == "unknown" and item["provenance"] == "agent_proposed" for item in ui["checks"])


def test_complete_manifest_is_hash_bound_but_retains_zero_authority(tmp_path: Path):
    result = verify_quality_harness(tmp_path, _write_manifest(tmp_path))
    assert result["decision"] == "READY_FOR_HUMAN_RELEASE_REVIEW"
    assert result["findings"] == []
    assert len(result["checks"]) == 19
    assert set(result["evidence_classes"]) == {"deterministic", "heuristic"}
    assert all(value is False for value in result["authority"].values())
    assert result["review_identity"]["authenticated"] is False
    stored = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
    core = {key: value for key, value in stored.items() if key not in {"receipt_sha256", "generated_at"}}
    digest = hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    assert stored["receipt_sha256"] == digest
    assert "not authenticated identity" in stored["claim_boundary"]


def test_agent_cannot_approve_human_judgments(tmp_path: Path):
    path = _write_manifest(tmp_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["reviewer"] = {"name": "coding-agent", "type": "agent"}
    path.write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_quality_harness(tmp_path, path)
    assert result["decision"] == "BLOCKED"
    assert any(item["code"] == "E_UX_HUMAN_REVIEW_REQUIRED" for item in result["findings"])


def test_ui_check_cannot_be_omitted_or_reclassified_as_non_ui(tmp_path: Path):
    path = _write_manifest(tmp_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["checks"] = [item for item in manifest["checks"] if item["id"] != "ui.keyboard_navigation"]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_quality_harness(tmp_path, path)
    assert result["decision"] == "BLOCKED"
    assert result["findings"] == [{"code": "E_UX_CHECK_SET_MISMATCH", "detail": "expected exactly 19 closed check identifiers"}]


def test_agent_proposed_check_remains_blocked_even_when_marked_passed(tmp_path: Path):
    path = _write_manifest(tmp_path, ui=False)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["checks"][0]["provenance"] = "agent_proposed"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_quality_harness(tmp_path, path)
    assert result["decision"] == "BLOCKED"
    assert any(item["code"] == "E_UX_CHECK_PROVENANCE" for item in result["findings"])


def test_short_or_rejected_human_rationale_blocks(tmp_path: Path):
    path = _write_manifest(tmp_path, ui=False)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["judgments"][0].update(approved=False, rationale="too short")
    path.write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_quality_harness(tmp_path, path)
    assert result["decision"] == "BLOCKED"
    assert {item["code"] for item in result["findings"]} == {"E_UX_HUMAN_REVIEW_REQUIRED"}


def test_evidence_path_escape_is_rejected(tmp_path: Path):
    path = _write_manifest(tmp_path, ui=False)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["checks"][0]["evidence"] = ["../outside.json"]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(FullStackUXHarnessError) as caught:
        verify_quality_harness(tmp_path, path)
    assert caught.value.code == "E_UX_EVIDENCE_PATH"


def test_receipt_cannot_replace_manifest_even_with_equivalent_relative_path(tmp_path: Path):
    path = _write_manifest(tmp_path, ui=False)
    with pytest.raises(FullStackUXHarnessError) as caught:
        verify_quality_harness(tmp_path, path, out=Path(".") / path.name)
    assert caught.value.code == "E_UX_RECEIPT_PATH"
    assert json.loads(path.read_text(encoding="utf-8"))["schema"] == "factory.full-stack-ux-harness.manifest.v1"


def test_unknown_manifest_fields_are_rejected_instead_of_ignored(tmp_path: Path):
    path = _write_manifest(tmp_path, ui=False)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["release_override"] = True
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(FullStackUXHarnessError) as caught:
        verify_quality_harness(tmp_path, path)
    assert caught.value.code == "E_UX_MANIFEST_SCHEMA"


def test_duplicate_evidence_is_blocked(tmp_path: Path):
    path = _write_manifest(tmp_path, ui=False)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["checks"][0]["evidence"] = ["native-checks.json", "native-checks.json"]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_quality_harness(tmp_path, path)
    assert result["decision"] == "BLOCKED"
    assert any(item["code"] == "E_UX_CHECK_EVIDENCE_DUPLICATE" for item in result["findings"])


def test_cli_writes_template_and_returns_nonzero_until_review_is_complete(tmp_path: Path, capsys):
    assert main(["quality-harness", "template", "--root", str(tmp_path), "--ui", "--out", "quality.json", "--json"]) == 0
    template = json.loads(capsys.readouterr().out)
    assert Path(template["path"]).is_file()
    assert main(["quality-harness", "verify", "quality.json", "--root", str(tmp_path), "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["decision"] == "BLOCKED"


def test_frontend_diff_routes_to_quality_harness_and_prestige(tmp_path: Path):
    result = optimize_pr(tmp_path, changed=["src/App.tsx"], feature="ui")
    assert "quality-harness:verify" in result["recommended_stages"]
    assert "prestige:audit" in result["recommended_stages"]


def test_intent_envelope_binds_the_approved_quality_harness_spec():
    root = Path(__file__).parents[1]
    spec = (root / "specs" / "full-stack-ux-harness-v1.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    envelope = json.loads((root / "envelopes" / "full-stack-ux-harness-v1.json").read_text(encoding="utf-8"))
    assert envelope["source"] == "specs/full-stack-ux-harness-v1.md"
    assert envelope["sealed_hash"] == hashlib.sha256(spec.encode("utf-8")).hexdigest()
    assert envelope["coherence_score"] == 100
    assert envelope["assumptions"]
