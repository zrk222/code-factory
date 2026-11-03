import copy
import hashlib
import json

import pytest

from factoryline import primitive_observation_binding as binding
from factoryline import review_audits


@pytest.fixture
def scan(tmp_path):
    (tmp_path / "app.py").write_text(
        "import sqlite3\nvalue = 1\n",
        encoding="utf-8",
    )
    (tmp_path / "factory.database.json").write_text(
        json.dumps(
            {"schema": "factory.database-context-config.v1", "dialect": "sqlite"}
        ),
        encoding="utf-8",
    )
    report = review_audits.security_scan(
        tmp_path,
        cache_enabled=False,
        defect_policy="source-role-v3",
        security_only=True,
    )
    captured = dict(report._captured_sources)
    assert (
        captured["factory.database.json"]
        == (tmp_path / "factory.database.json").read_bytes()
    )
    return copy.deepcopy(dict(report)), captured


def test_database_configuration_is_bound_and_regenerated(scan):
    core, captured = scan
    assert core["database_context"]["status"] == "COMPLETE"
    assert core["database_context"]["gaps"] == []
    policy = core["defect_policy_decision"]
    assert policy["state"] == "NO_SUPPORTED_DEFECTS_REVIEW_REQUIRED"
    assert policy["admission"]["source_sha256"]
    assert policy["admission"]["evidence_sha256"]
    assert policy["clean"] is False
    assert policy["release_approved"] is False
    rows = core["oracle_context"]["configuration_sources"]
    row = next(row for row in rows if row["path"] == "factory.database.json")
    assert row in core["database_context"]["configuration_sources"]
    assert (
        binding._trusted_core_complete_sources(core, captured, review_audits)[0]
        == captured
    )
    regenerated, source_hash, native = binding._trusted_core_regenerated_tiers(
        core, captured
    )
    assert regenerated is not None
    assert source_hash is not None
    assert native is not None
    decision = binding.security_defect_policy_decision(core, captured)
    assert decision["state"] == "NO_SUPPORTED_DEFECTS_REVIEW_REQUIRED"
    assert decision["source_sha256"] and decision["evidence_sha256"]
    assert decision["clean"] is False
    assert decision["release_approved"] is False


@pytest.mark.parametrize(
    "fault",
    [
        "wrong_name",
        "outside",
        "wrong_hash",
        "tamper",
        "wrong_size",
        "identity",
        "malformed",
        "duplicate",
    ],
)
def test_database_configuration_rejects_invalid_binding(scan, fault):
    core, captured = scan
    oracle = core["oracle_context"]["configuration_sources"]
    row = next(row for row in oracle if row["path"] == "factory.database.json")
    database_row = next(
        row
        for row in core["database_context"]["configuration_sources"]
        if row["path"] == "factory.database.json"
    )
    if fault in {"wrong_name", "outside"}:
        row["path"] = (
            "other.database.json"
            if fault == "wrong_name"
            else "../factory.database.json"
        )
        database_row["path"] = row["path"]
    elif fault == "wrong_hash":
        row["sha256"] = database_row["sha256"] = "0" * 64
    elif fault == "tamper":
        captured["factory.database.json"] += b" "
    elif fault == "wrong_size":
        row["bytes"] = database_row["bytes"] = 1
    elif fault == "identity":
        database_row["sha256"] = "0" * 64
    elif fault == "malformed":
        raw = b'{"schema":"factory.database-context-config.v1","dialect":"sqlite","dialect":"sqlite"}'
        captured["factory.database.json"] = raw
        row["sha256"] = database_row["sha256"] = hashlib.sha256(raw).hexdigest()
        row["bytes"] = database_row["bytes"] = len(raw)
    else:
        oracle.append(copy.deepcopy(row))
    assert binding._trusted_core_complete_sources(core, captured, review_audits) is None


def test_database_filename_is_not_an_application_configuration():
    row = {"path": "factory.database.json", "sha256": "a" * 64}
    assert binding._trusted_core_source_binding(row, configuration=True) is None
    assert binding._trusted_core_source_binding(
        row, configuration=True, database_configuration=True
    ) == (row["path"], row["sha256"])


def test_database_configuration_change_before_retention_is_rejected(
    tmp_path, monkeypatch
):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    config = tmp_path / "factory.database.json"
    config.write_text(
        json.dumps(
            {"schema": "factory.database-context-config.v1", "dialect": "sqlite"}
        ),
        encoding="utf-8",
    )
    original = review_audits._verify_security_bindings

    def change_before_capture(workspace, rows, *, captured_out=None):
        if captured_out is not None and any(
            row.get("path") == "factory.database.json" for row in rows
        ):
            config.write_text("{}", encoding="utf-8")
        return original(workspace, rows, captured_out=captured_out)

    monkeypatch.setattr(
        review_audits, "_verify_security_bindings", change_before_capture
    )
    with pytest.raises(review_audits.ReviewAuditError, match="changed"):
        review_audits.security_scan(
            tmp_path,
            cache_enabled=False,
            defect_policy="source-role-v3",
            security_only=True,
        )
