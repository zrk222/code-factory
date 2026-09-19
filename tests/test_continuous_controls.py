from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.continuous_controls import (
    ControlsError,
    build_control_graph,
    continuous_controls_projection,
    create_exception,
    evaluate_controls,
    fleet_coverage,
    load_policy_pack,
    render_controls_review,
    verify_control_evaluation,
    write_control_evaluation,
    write_controls_dossier,
)


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _control(
    cid: str = "CTRL-001",
    *,
    threshold: int = 0,
    severity: str = "HIGH",
    provenance: str = "human_confirmed",
    evidence: list[str] | None = None,
) -> dict:
    return {
        "id": cid,
        "title": "No unsafe output",
        "description": "The output must not contain the forbidden behavior.",
        "forbidden_behavior": "unsafe output reaches production",
        "gate": {
            "id": f"gate-{cid}",
            "kind": "receipt",
            "threshold": {"operator": "lte", "value": threshold},
        },
        "test": {"id": f"test-{cid}", "kind": "independent_receipt"},
        "required_evidence": evidence or ["receipt"],
        "severity": severity,
        "provenance": {
            "kind": provenance,
            "source": "human policy",
            "source_sha256": "a" * 64,
        },
        "remediation": f"Supply a fresh receipt for {cid}",
    }


def _pack(
    *,
    controls: list[dict] | None = None,
    kind: str = "human_confirmed",
    author: str = "alice",
    approver: str = "bob",
    parent: dict | None = None,
) -> dict:
    return {
        "schema": "factory.policy-pack.v1",
        "pack_id": "team-baseline",
        "version": "1.0.0",
        "provenance": {
            "kind": kind,
            "source": "reviewed baseline",
            "source_sha256": "b" * 64,
        },
        "authorship": {"author": author},
        "approval": {
            "approver": approver,
            "decision": "approved",
            "approved_at": "2026-01-01T00:00:00Z",
            "approval_sha256": "c" * 64,
        },
        "parent": parent,
        "exception_policy": {"max_ttl_days": 30},
        "controls": controls or [_control()],
    }


def _sealed_receipt(root: Path, control_id: str = "CTRL-001") -> str:
    path = root / "evidence" / f"{control_id}.json"
    payload = {
        "control_id": control_id,
        "verdict": "PASS",
        "source": "independent-run",
        "generated_at": "2026-01-01T00:00:00Z",
    }
    envelope = dict(payload)
    envelope["receipt_sha256"] = _digest(payload)
    _write(path, envelope)
    return path.as_posix()


def test_provenance_and_inheritance_are_visible(tmp_path: Path) -> None:
    parent = tmp_path / "controls" / "parent.json"
    _write(parent, _pack(controls=[_control("CTRL-PARENT")]))
    child = tmp_path / "controls" / "child.json"
    _write(
        child,
        _pack(
            controls=[_control("CTRL-CHILD")],
            parent={
                "path": "parent.json",
                "sha256": hashlib.sha256(parent.read_bytes()).hexdigest(),
            },
        ),
    )
    resolved = load_policy_pack(tmp_path, "controls/child.json")
    assert resolved["status"] == "ENFORCED"
    assert resolved["inherited_control_ids"] == ["CTRL-PARENT"]
    assert {item["id"] for item in resolved["controls"]} == {
        "CTRL-PARENT",
        "CTRL-CHILD",
    }

    nested_parent = tmp_path / "org-parent.json"
    _write(nested_parent, _pack(controls=[_control("CTRL-ORG")]))
    nested_child = tmp_path / "controls" / "nested.json"
    _write(
        nested_child,
        _pack(
            controls=[],
            parent={
                "path": "../org-parent.json",
                "sha256": hashlib.sha256(nested_parent.read_bytes()).hexdigest(),
            },
        ),
    )
    assert "CTRL-ORG" in {
        item["id"]
        for item in load_policy_pack(tmp_path, "controls/nested.json")["controls"]
    }

    proposed = tmp_path / "controls" / "proposed.json"
    _write(proposed, _pack(kind="agent_proposed", author="agent", approver="agent"))
    assert load_policy_pack(tmp_path, "controls/proposed.json")["status"] == "ADVISORY"


def test_weakening_and_deletion_fail_closed(tmp_path: Path) -> None:
    parent = tmp_path / "controls" / "parent.json"
    _write(parent, _pack(controls=[_control(threshold=0)]))
    weakened = tmp_path / "controls" / "child.json"
    child = _pack(controls=[_control(threshold=5)])
    child["parent"] = {
        "path": "parent.json",
        "sha256": hashlib.sha256(parent.read_bytes()).hexdigest(),
    }
    _write(weakened, child)
    with pytest.raises(ControlsError, match="cannot weaken") as error:
        load_policy_pack(tmp_path, "controls/child.json")
    assert error.value.code == "E_CONTROL_WEAKENING"

    deleted = tmp_path / "controls" / "deleted.json"
    deleted_value = _pack(controls=[])
    deleted_value["parent"] = {
        "path": "parent.json",
        "sha256": hashlib.sha256(parent.read_bytes()).hexdigest(),
    }
    deleted_value["remove_controls"] = ["CTRL-001"]
    _write(deleted, deleted_value)
    with pytest.raises(ControlsError) as deleted_error:
        load_policy_pack(tmp_path, "controls/deleted.json")
    assert deleted_error.value.code == "E_CONTROL_DELETED"


def test_evaluation_blocks_without_evidence_and_reports_drift(tmp_path: Path) -> None:
    policy = tmp_path / "controls" / "policy.json"
    _write(policy, _pack())
    evaluation = evaluate_controls(
        tmp_path,
        "controls/policy.json",
        baseline={"effective_sha256": "d" * 64},
        event={"kind": "deployment", "actor": "agent", "commit": "abc"},
    )
    assert evaluation["decision"] == "REVIEW_REQUIRED"
    assert evaluation["coverage"]["blocked"] == 1
    assert evaluation["drift"]["state"] == "BLOCKED"
    assert evaluation["next_action"]["control_id"] == "CTRL-001"
    assert evaluation["authority"] == {
        "release": False,
        "merge": False,
        "deploy": False,
        "credentials": False,
    }
    passed = evaluate_controls(
        tmp_path, "controls/policy.json", evidence_paths=[_sealed_receipt(tmp_path)]
    )
    assert passed["controls"][0]["status"] == "PASSED"
    assert passed["decision"] == "READY_FOR_HUMAN_REVIEW"


def test_exception_sod_ttl_and_expiry(tmp_path: Path) -> None:
    policy = tmp_path / "controls" / "policy.json"
    _write(policy, _pack())
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("approved compensating control\n", encoding="utf-8")
    exception = create_exception(
        tmp_path,
        "controls/policy.json",
        "CTRL-001",
        owner="ops",
        reason="hotfix",
        scope="release/123",
        ttl_days=7,
        evidence_path="evidence.txt",
        author="alice",
        approver="bob",
        out="controls/exception.json",
    )
    assert exception["status"] == "ACTIVE"
    assert exception["approval"]["approver"] == "bob"
    result = evaluate_controls(
        tmp_path, "controls/policy.json", exception_paths=["controls/exception.json"]
    )
    assert result["controls"][0]["status"] == "EXEMPT"
    with pytest.raises(ControlsError) as error:
        create_exception(
            tmp_path,
            "controls/policy.json",
            "CTRL-001",
            owner="ops",
            reason="bad",
            scope="all",
            ttl_days=31,
            evidence_path="evidence.txt",
            author="alice",
            approver="bob",
        )
    assert error.value.code == "E_EXCEPTION_TTL"


def test_graph_dossier_and_projection(tmp_path: Path) -> None:
    policy = tmp_path / "controls" / "policy.json"
    _write(policy, _pack())
    evaluation = evaluate_controls(tmp_path, "controls/policy.json")
    stored = write_control_evaluation(tmp_path, evaluation)
    graph = build_control_graph(evaluation)
    relations = [edge["relation"] for edge in graph["edges"]]
    assert relations[:6] == [
        "defines",
        "forbids",
        "guards",
        "challenged_by",
        "evidenced_by",
        "decides",
    ]
    assert graph["graph_sha256"]
    assert "One next action" in render_controls_review(evaluation)
    dossier = write_controls_dossier(tmp_path, evaluation)
    assert Path(tmp_path / dossier["json"]).is_file()
    projection = continuous_controls_projection(tmp_path)
    assert projection["evaluation_count"] == 1
    assert verify_control_evaluation(tmp_path, stored["path"])["verified"]


def test_fleet_coverage(tmp_path: Path) -> None:
    for name in ("one", "two"):
        repo = tmp_path / "repos" / name
        _write(
            repo / "controls" / "policy.json",
            _pack(controls=[_control("CTRL-001" if name == "one" else "CTRL-002")]),
        )
    fleet = {
        "schema": "factory.control-fleet.v1",
        "baseline_controls": ["CTRL-001", "CTRL-002"],
        "repositories": [
            {"id": "one", "path": "repos/one", "policy": "controls/policy.json"},
            {"id": "two", "path": "repos/two", "policy": "controls/policy.json"},
        ],
    }
    _write(tmp_path / "controls" / "fleet.json", fleet)
    result = fleet_coverage(tmp_path)
    assert result["repositories"][0]["missing_baseline"]
    assert result["repositories"][1]["missing_baseline"]
