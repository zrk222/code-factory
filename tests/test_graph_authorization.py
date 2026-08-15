from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from factoryline.graph_authorization import (
    GraphAuthorizationError,
    create_graph_authorization,
    run_authorized_reality_check,
    validate_graph_authorization,
)
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.reality_check import run_reality_check, write_reality_check_artifacts


def _prepared_reality(root: Path) -> str:
    from test_reality_check import _write

    receipt = run_reality_check(root, _write(root))
    write_reality_check_artifacts(receipt, root / ".factory" / "reality")
    return next(node["id"] for node in graph_ops_snapshot(root)["nodes"] if node["kind"] == "reality_check")


def _payload(node_id: str, *, authorization_id: str = "run-approval") -> dict[str, str]:
    return {
        "action": "reality_check_execution", "id": authorization_id, "node_id": node_id,
        "approved_by": "release-owner", "rationale": "The declared intent needs one fresh local proof.",
        "expires_at": "2026-08-15T13:00:00Z", "confirmation": f"AUTHORIZE {authorization_id}",
    }


def test_graph_authorization_binds_a_verified_reality_check_and_consumes_once(tmp_path: Path):
    node_id = _prepared_reality(tmp_path)
    now = datetime(2026, 8, 15, 12, tzinfo=timezone.utc)
    result = create_graph_authorization(tmp_path, _payload(node_id), now=now)

    authorization = result["authorization"]
    assert result["marker"] == "GRAPH_OPS_HUMAN_AUTHORIZATION_RECORDED"
    assert authorization["binding"]["node_id"] == node_id
    assert authorization["authority"]["execution"] is True
    assert authorization["authority"]["repair"] is False
    assert validate_graph_authorization(authorization)["state"] == "approved"
    projected = graph_ops_snapshot(tmp_path)
    assert "GRAPH_OPS_HUMAN_AUTHORIZATIONS_PROJECTED" in projected["markers"]
    assert projected["facts"]["graph_authorization_approved_count"] == 1
    assert next(node for node in projected["nodes"] if node["kind"] == "authorization")["status"] == "approved"

    executed = run_authorized_reality_check(tmp_path, Path(result["path"]), now=now + timedelta(minutes=1))
    assert executed["marker"] == "GRAPH_OPS_AUTHORIZED_REALITY_CHECK_EXECUTED"
    assert executed["receipt"]["marker"] == "REALITY_CHECK_VERIFIED"
    assert Path(executed["outputs"]["receipt"]).name.endswith(".reality.json")

    consumed = validate_graph_authorization(json.loads(Path(result["path"]).read_text(encoding="utf-8")))
    assert consumed["state"] == "consumed"
    with pytest.raises(GraphAuthorizationError, match="unused Reality Check"):
        run_authorized_reality_check(tmp_path, Path(result["path"]), now=now + timedelta(minutes=2))


def test_graph_authorization_requires_confirmation_and_rejects_changed_bound_receipt(tmp_path: Path):
    node_id = _prepared_reality(tmp_path)
    now = datetime(2026, 8, 15, 12, tzinfo=timezone.utc)
    denied = _payload(node_id, authorization_id="denied")
    denied["confirmation"] = "yes"
    with pytest.raises(GraphAuthorizationError, match="confirmation"):
        create_graph_authorization(tmp_path, denied, now=now)

    result = create_graph_authorization(tmp_path, _payload(node_id, authorization_id="stale"), now=now)
    source = Path(result["authorization"]["binding"]["source"])
    receipt_path = tmp_path / source
    receipt_path.write_text("{}", encoding="utf-8")
    with pytest.raises(GraphAuthorizationError, match="changed after approval"):
        run_authorized_reality_check(tmp_path, Path(result["path"]), now=now + timedelta(minutes=1))


def test_graph_authorization_rejects_a_concurrent_execution_lock(tmp_path: Path):
    node_id = _prepared_reality(tmp_path)
    now = datetime(2026, 8, 15, 12, tzinfo=timezone.utc)
    result = create_graph_authorization(tmp_path, _payload(node_id, authorization_id="locked"), now=now)
    lock = Path(result["path"]).with_suffix(".json.lock")
    lock.write_text("in progress\n", encoding="utf-8")

    with pytest.raises(GraphAuthorizationError, match="already executing"):
        run_authorized_reality_check(tmp_path, Path(result["path"]), now=now + timedelta(minutes=1))
