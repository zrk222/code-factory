"""Adversarial probes for Code Factory's own local authority contracts.

Each case is derived from the product's own module contracts
(factoryline/semantic_authority.py, graph_authorization.py), not from any
external test material. Local synthetic workspaces only; no network.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from factoryline import compat_sha as _sha
from factoryline.graph_authorization import (
    GraphAuthorizationError,
    create_graph_authorization,
    run_authorized_reality_check,
    validate_graph_authorization,
)
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.reality_check import run_reality_check, write_reality_check_artifacts
from factoryline.semantic_authority import (
    SemanticAuthorityError,
    authorize_semantic_action,
    record_semantic_action_decision,
    seal_authority_lease,
    seal_semantic_handoff,
    verify_semantic_binding,
)

from test_semantic_authority import (
    RECEIVER,
    _contract,
    _handoff,
    _lease,
    _request,
    _write,
)


# --- semantic authority: bounded-fact rejections ---------------------------


def test_binding_with_extra_unapproved_field_is_rejected(tmp_path: Path) -> None:
    handoff = _handoff(tmp_path, _contract(tmp_path))
    lease = _lease(tmp_path, handoff)
    binding = {
        "lease_path": lease.relative_to(tmp_path).as_posix(),
        "lease_sha256": json.loads(lease.read_text(encoding="utf-8"))["lease_sha256"],
        "action_id": "check-restore",
        "action": "test",
        "context_urn": "urn:factory:subscription-restore:v1",
        "forwarded_note": "an unapproved extra field",
    }
    with pytest.raises(SemanticAuthorityError):
        verify_semantic_binding(tmp_path, binding, RECEIVER, ["tests"])


def test_empty_evidence_lists_cannot_seal_a_handoff(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    _handoff(tmp_path, contract)  # writes the valid semantic-input.json payload
    payload_path = tmp_path / "semantic-input.json"
    pristine = json.loads(payload_path.read_text(encoding="utf-8"))
    for field in ("known", "unknown", "uncertain"):
        payload = json.loads(json.dumps(pristine))
        payload["id"] = f"empty-{field}"
        payload["epistemic"][field] = []
        payload_path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(SemanticAuthorityError) as exc:
            seal_semantic_handoff(
                tmp_path,
                payload_path,
                Path(f".factory/semantic-authority/handoffs/empty-{field}.json"),
            )
        assert exc.value.code == "SEMANTIC_EPISTEMIC_INVALID"


def test_mixed_case_forbidden_action_never_enters_a_handoff(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    _handoff(tmp_path, contract)
    payload_path = tmp_path / "semantic-input.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    for action in ("Merge", "PUBLISH", "Deploy"):
        payload["id"] = f"sneaky-{action.lower()}"
        payload["allowed_actions"] = [action]
        payload_path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(SemanticAuthorityError) as exc:
            seal_semantic_handoff(
                tmp_path,
                payload_path,
                Path(f".factory/semantic-authority/handoffs/sneaky-{action.lower()}.json"),
            )
        assert exc.value.code == "SEMANTIC_ACTION_FORBIDDEN"


def test_sibling_prefix_is_not_inside_scope(tmp_path: Path) -> None:
    handoff = _handoff(tmp_path, _contract(tmp_path))  # scope: src, tests
    lease = _lease(tmp_path, handoff)
    escaped = _request(scope_paths=["tests-evil"])
    decision = authorize_semantic_action(tmp_path, lease, escaped)
    assert decision["allowed"] is False
    assert decision["reason"] == "scope_escape"
    lease_payload_path = tmp_path / "lease-input.json"
    lease_payload = json.loads(lease_payload_path.read_text(encoding="utf-8"))
    lease_payload["id"] = "widened"
    lease_payload["scope_paths"] = ["src2"]
    lease_payload_path.write_text(json.dumps(lease_payload), encoding="utf-8")
    with pytest.raises(SemanticAuthorityError) as exc:
        seal_authority_lease(
            tmp_path, lease_payload_path, Path(".factory/semantic-authority/leases/widened.json")
        )
    assert exc.value.code == "E_SEMANTIC_AUTHORIZATION"


def test_expired_lease_denies_action_and_decision_recording(tmp_path: Path, monkeypatch) -> None:
    handoff = _handoff(tmp_path, _contract(tmp_path))
    lease = _lease(tmp_path, handoff)  # expires 20 minutes from real now
    later = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=21)
    monkeypatch.setattr("factoryline.semantic_authority._now", lambda: later)
    decision = authorize_semantic_action(tmp_path, lease, _request())
    assert decision["allowed"] is False
    assert decision["reason"] == "SEMANTIC_LEASE_EXPIRED"
    with pytest.raises(SemanticAuthorityError):
        record_semantic_action_decision(
            tmp_path, lease, _request(), Path(".factory/semantic-authority/decisions/x.json")
        )


def test_action_id_replay_under_same_lease_is_rejected(tmp_path: Path) -> None:
    handoff = _handoff(tmp_path, _contract(tmp_path))
    lease = _lease(tmp_path, handoff)
    out = Path(
        ".factory/semantic-authority/decisions/"
        + json.loads(lease.read_text(encoding="utf-8"))["lease_sha256"]
        + "-check-restore.json"
    )
    record_semantic_action_decision(tmp_path, lease, _request(), out)
    with pytest.raises(SemanticAuthorityError) as exc:
        record_semantic_action_decision(tmp_path, lease, _request(), out)
    assert exc.value.code == "E_SEMANTIC_REPLAY"


# --- graph authorization: one-shot human authorization ---------------------


def _prepared_reality(root: Path) -> str:
    from test_first_lap import _write as write_manifest

    receipt = run_reality_check(root, write_manifest(root))
    write_reality_check_artifacts(receipt, root / ".factory" / "reality")
    return next(
        node["id"] for node in graph_ops_snapshot(root)["nodes"] if node["kind"] == "reality_check"
    )


def _payload(node_id: str, authorization_id: str = "run-approval") -> dict[str, str]:
    return {
        "action": "reality_check_execution",
        "id": authorization_id,
        "node_id": node_id,
        "approved_by": "release-owner",
        "rationale": "The declared intent needs one fresh local proof.",
        "expires_at": "2026-08-15T13:00:00Z",
        "confirmation": f"AUTHORIZE {authorization_id}",
    }


def test_expired_authorization_cannot_execute(tmp_path: Path) -> None:
    node_id = _prepared_reality(tmp_path)
    now = datetime(2026, 8, 15, 12, tzinfo=timezone.utc)
    result = create_graph_authorization(tmp_path, _payload(node_id), now=now)
    with pytest.raises(GraphAuthorizationError, match="expired"):
        run_authorized_reality_check(
            tmp_path, Path(result["path"]), now=now + timedelta(hours=1, minutes=1)
        )


def test_authorization_id_cannot_be_reused(tmp_path: Path) -> None:
    node_id = _prepared_reality(tmp_path)
    now = datetime(2026, 8, 15, 12, tzinfo=timezone.utc)
    create_graph_authorization(tmp_path, _payload(node_id), now=now)
    with pytest.raises(GraphAuthorizationError, match="already exists"):
        create_graph_authorization(tmp_path, _payload(node_id), now=now)


def test_authorization_path_cannot_escape_the_workspace(tmp_path: Path) -> None:
    node_id = _prepared_reality(tmp_path)
    now = datetime(2026, 8, 15, 12, tzinfo=timezone.utc)
    result = create_graph_authorization(tmp_path, _payload(node_id), now=now)
    outside = tmp_path.parent / "outside-authorization.json"
    outside.write_text(Path(result["path"]).read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(GraphAuthorizationError, match="inside the workspace"):
        run_authorized_reality_check(tmp_path, outside, now=now + timedelta(minutes=1))
    with pytest.raises(GraphAuthorizationError):
        run_authorized_reality_check(tmp_path, Path("../outside-authorization.json"), now=now)


def test_repair_plan_authorization_cannot_execute_a_reality_check(tmp_path: Path) -> None:
    node_id = _prepared_reality(tmp_path)
    now = datetime(2026, 8, 15, 12, tzinfo=timezone.utc)
    result = create_graph_authorization(tmp_path, _payload(node_id), now=now)
    forged = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
    forged["action"] = "repair_plan_review"
    forged["authority"] = {key: False for key in forged["authority"]}
    core = {key: forged[key] for key in forged if key != "authorization_sha256"}
    forged["authorization_sha256"] = _sha(core)
    forged_path = tmp_path / ".factory" / "graph-ops" / "authorizations" / "forged-action.json"
    forged_path.write_text(json.dumps(forged), encoding="utf-8")
    assert validate_graph_authorization(forged)["action"] == "repair_plan_review"
    with pytest.raises(GraphAuthorizationError, match="not an unused Reality Check"):
        run_authorized_reality_check(tmp_path, forged_path, now=now + timedelta(minutes=1))


def test_failed_run_consumes_the_single_authorization(tmp_path: Path) -> None:
    node_id = _prepared_reality(tmp_path)
    now = datetime(2026, 8, 15, 12, tzinfo=timezone.utc)
    result = create_graph_authorization(tmp_path, _payload(node_id), now=now)
    # Sabotage the run environment without touching any hash-bound bytes:
    # the positive command writes proof.txt, so a directory at that path fails it.
    (tmp_path / "proof.txt").unlink()  # left over from the preparation run
    (tmp_path / "proof.txt").mkdir()
    executed = run_authorized_reality_check(tmp_path, Path(result["path"]), now=now + timedelta(minutes=1))
    assert executed["receipt"]["ok"] is False
    consumed = validate_graph_authorization(
        json.loads(Path(result["path"]).read_text(encoding="utf-8"))
    )
    assert consumed["state"] == "consumed"
    # Repair the environment; the single authorization must still be gone.
    (tmp_path / "proof.txt").rmdir()
    with pytest.raises(GraphAuthorizationError, match="not an unused Reality Check"):
        run_authorized_reality_check(tmp_path, Path(result["path"]), now=now + timedelta(minutes=2))
