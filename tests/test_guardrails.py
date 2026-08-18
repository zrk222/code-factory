from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.continuity import ContinuityPrincipal, ContinuityStore
from factoryline.guardrails import GuardrailError, evaluate_guardrails, verify_guardrail_evaluation


PURPOSE = "delivery-review@1"
SCOPE = "repo:sha256:checkout"


def _principal(subject: str, roles: tuple[str, ...]) -> ContinuityPrincipal:
    return ContinuityPrincipal(subject, "tenant-a", roles, (PURPOSE,))


def _record() -> dict:
    return {
        "schema": "factory.continuity.record.v1",
        "tenant_id": "tenant-a",
        "record_type": "decision",
        "memory_ref": "memory://engineering/checkout-approval",
        "purpose": {"id": "delivery-review", "version": "1"},
        "scope": {"repository_ref": SCOPE},
        "evidence_refs": ["receipt:sha256:checkout-proof"],
        "summary": "This must never leave the continuity metadata store.",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    }


def _manifest(path: Path) -> Path:
    value = {
        "schema": "factory.guardrail-manifest.v1",
        "id": "checkout-guardrails",
        "tenant_id": "tenant-a",
        "purpose": PURPOSE,
        "scope": SCOPE,
        "guardrails": [
            {"id": "checkout-auth", "record_id": "promoted-record", "path_prefixes": ["src/checkout"], "required_risk_tags": ["authorization", "validation"]},
            {"id": "draft-withheld", "record_id": "draft-record", "path_prefixes": ["src/checkout"], "required_risk_tags": ["idempotency"]},
        ],
    }
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _store(path: Path) -> ContinuityStore:
    store = ContinuityStore(path)
    store.record(_principal("writer", ("writer",)), _record(), idempotency_key="promoted", record_id="promoted-record")
    store.promote(_principal("reviewer", ("promoter",)), "tenant-a", "promoted-record", reason="independent evidence review")
    store.record(_principal("writer", ("writer",)), _record(), idempotency_key="draft", record_id="draft-record")
    return store


def test_guardrails_only_activate_promoted_exact_scope_metadata_and_redact_content(tmp_path: Path):
    db = tmp_path / "continuity.sqlite3"
    _store(db)
    manifest = _manifest(tmp_path / "guardrails.json")
    before = db.read_bytes()

    evaluation = evaluate_guardrails(manifest, db, _principal("reader", ("reader",)), changed_paths=["src/checkout/submit.py", "docs/readme.md"])
    after = db.read_bytes()
    rows = {row["id"]: row for row in evaluation["guardrails"]}
    assert rows["checkout-auth"]["status"] == "active"
    assert rows["checkout-auth"]["matched_paths"] == ["src/checkout/submit.py"]
    assert rows["draft-withheld"]["status"] == "withheld"
    assert rows["draft-withheld"]["withheld_reason"] == "GUARDRAIL_WITHHELD"
    encoded = json.dumps(evaluation)
    assert "memory://" not in encoded
    assert "must never leave" not in encoded
    assert before == after
    assert verify_guardrail_evaluation(evaluation)["evaluation_sha256"] == evaluation["evaluation_sha256"]


def test_guardrails_do_not_initialize_missing_continuity_or_accept_tampering(tmp_path: Path):
    manifest = _manifest(tmp_path / "guardrails.json")
    missing = tmp_path / "does-not-exist.sqlite3"
    with pytest.raises(GuardrailError) as unavailable:
        evaluate_guardrails(manifest, missing, _principal("reader", ("reader",)), changed_paths=["src/checkout/submit.py"])
    assert unavailable.value.code == "GUARDRAIL_CONTINUITY_UNAVAILABLE"
    assert missing.exists() is False

    db = tmp_path / "continuity.sqlite3"
    _store(db)
    evaluation = evaluate_guardrails(manifest, db, _principal("reader", ("reader",)), changed_paths=["src/checkout/submit.py"])
    evaluation["guardrails"][0]["status"] = "inactive"
    with pytest.raises(GuardrailError) as tampered:
        verify_guardrail_evaluation(evaluation)
    assert tampered.value.code == "GUARDRAIL_EVALUATION_TAMPERED"


def test_guardrail_cli_emits_hash_bound_redacted_evaluation(tmp_path: Path, capsys):
    db = tmp_path / "continuity.sqlite3"
    _store(db)
    manifest = _manifest(tmp_path / "guardrails.json")
    assert main(["guardrail", "evaluate", str(manifest), "--db", str(db), "--tenant", "tenant-a", "--subject", "reader", "--purposes", PURPOSE, "--changed", "src/checkout/submit.py", "--json"]) == 0
    evaluation = json.loads(capsys.readouterr().out)
    assert evaluation["marker"] == "GUARDRAIL_EVALUATED"
    saved = tmp_path / "evaluation.json"
    saved.write_text(json.dumps(evaluation), encoding="utf-8")
    assert main(["guardrail", "verify", str(saved), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "GUARDRAIL_EVALUATED"
