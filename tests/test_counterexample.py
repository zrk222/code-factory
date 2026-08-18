from __future__ import annotations

import hashlib
import json
from pathlib import Path

from factoryline.cli import main
from factoryline.counterexample import compile_counterexample_plan, verify_counterexample_plan, write_counterexample_plan


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _source() -> dict:
    return {
        "schema": "factory.counterexample-source.v1",
        "id": "approval-flow",
        "requirements": [
            {"id": "REQ-001", "statement": "Only an approver can release a change.", "risk_tags": ["authorization", "validation"]},
            {"id": "REQ-002", "statement": "A retry cannot duplicate an external effect.", "risk_tags": ["idempotency", "temporal"]},
        ],
    }


def _reseal(plan: dict) -> dict:
    core = {key: value for key, value in plan.items() if key != "plan_sha256"}
    return {**core, "plan_sha256": _digest(core)}


def test_counterexample_compiler_is_complete_hash_sealed_and_read_only(tmp_path: Path):
    source = tmp_path / "specs" / "approval.counterexamples.json"
    source.parent.mkdir()
    source.write_text(json.dumps(_source()), encoding="utf-8")

    plan = compile_counterexample_plan(tmp_path, source)
    out = tmp_path / ".factory" / "counterexamples" / "approval.plan.json"
    write_counterexample_plan(plan, out)

    verified = verify_counterexample_plan(tmp_path, out)
    assert verified["ok"] is True
    assert verified["case_count"] == 4
    assert all(value is False for value in plan["authority"].values())
    assert {case["risk_tag"] for case in plan["cases"]} == {"authorization", "validation", "idempotency", "temporal"}


def test_counterexample_verifier_rejects_semantic_deletion_tamper_and_stale_source(tmp_path: Path):
    source = tmp_path / "specs" / "approval.counterexamples.json"
    source.parent.mkdir()
    source.write_text(json.dumps(_source()), encoding="utf-8")
    out = tmp_path / "counterexamples.json"
    write_counterexample_plan(compile_counterexample_plan(tmp_path, source), out)

    hollow = json.loads(out.read_text(encoding="utf-8"))
    hollow["cases"] = hollow["cases"][:-1]
    out.write_text(json.dumps(_reseal(hollow)), encoding="utf-8")
    assert verify_counterexample_plan(tmp_path, out)["marker"] == "HOLLOW_COUNTEREXAMPLE"

    tampered = json.loads(out.read_text(encoding="utf-8"))
    tampered["plan_sha256"] = "0" * 64
    out.write_text(json.dumps(tampered), encoding="utf-8")
    assert verify_counterexample_plan(tmp_path, out)["marker"] == "COUNTEREXAMPLE_PLAN_TAMPERED"

    write_counterexample_plan(compile_counterexample_plan(tmp_path, source), out)
    changed = _source()
    changed["requirements"][0]["statement"] = "An approver must provide independent release evidence."
    source.write_text(json.dumps(changed), encoding="utf-8")
    assert verify_counterexample_plan(tmp_path, out)["marker"] == "COUNTEREXAMPLE_SOURCE_STALE"


def test_counterexample_cli_writes_only_explicit_output_and_verifies(tmp_path: Path, capsys):
    source = tmp_path / "specs" / "approval.counterexamples.json"
    source.parent.mkdir()
    source.write_text(json.dumps(_source()), encoding="utf-8")
    out = tmp_path / ".factory" / "counterexamples" / "approval.plan.json"

    assert main(["counterexample", "plan", str(source.relative_to(tmp_path)), "--root", str(tmp_path), "--out", str(out), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["marker"] == "COUNTEREXAMPLE_PLAN_COMPILED"
    assert out.is_file()
    assert main(["counterexample", "verify", str(out.relative_to(tmp_path)), "--root", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "COUNTEREXAMPLE_PLAN_VERIFIED"
