from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

from factoryline.atomic_review_audit import (
    CONTRACT_SCHEMA,
    RECEIPT_SCHEMA,
    ROUND_SCHEMA,
    ReviewConvergenceError,
    evaluate_review_round,
    read_convergence_receipt,
)
from factoryline.cli import main
from factoryline.mcp import dispatch


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_json(root: Path, name: str, value: object) -> str:
    (root / name).write_text(json.dumps(value), encoding="utf-8")
    return name


def _contract(reviewers: tuple[str, ...] = ("reviewer-a", "reviewer-b")) -> dict:
    return {
        "schema": CONTRACT_SCHEMA,
        "contract_id": "payment-review",
        "intent_sha256": _hash("intent"),
        "origin": "human_confirmed",
        "reviewer_ids": list(reviewers),
        "criteria": [
            {
                "id": "authz",
                "obligation_id": "AUTH-01",
                "statement_sha256": _hash("tenant isolation is required"),
                "origin": "human_confirmed",
            },
            {
                "id": "recovery",
                "obligation_id": "REC-01",
                "statement_sha256": _hash("retries are idempotent"),
                "origin": "trusted_source",
            },
        ],
    }


def _finding(
    *,
    title: str = "Tenant key is not checked",
    priority: int | None = 3,
    alignment: str = "required_by_objective",
) -> dict:
    return {
        "code": "TENANT_SCOPE",
        "title": title,
        "path": "src/export.py",
        "symbol": "export_records",
        "priority": priority,
        "alignment": alignment,
    }


def _round(
    contract: dict,
    *,
    finding: dict | None = None,
    overrides: dict[str, list[dict]] | None = None,
    round_id: str = "round-1",
    candidate: str = "candidate-1",
) -> dict:
    contract_digest = hashlib.sha256(
        json.dumps(
            contract, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    reviews = []
    overrides = overrides or {}
    for reviewer in contract["reviewer_ids"]:
        responses = []
        for criterion in contract["criteria"]:
            if reviewer in overrides and criterion["id"] == "authz":
                responses.extend(overrides[reviewer])
                continue
            selected = (
                [dict(finding)]
                if finding is not None and criterion["id"] == "authz"
                else []
            )
            responses.append(
                {
                    "criterion_id": criterion["id"],
                    "outcome": "finding" if selected else "supported",
                    "findings": selected,
                }
            )
        reviews.append(
            {
                "reviewer_id": reviewer,
                "evidence_sha256": _hash(f"evidence:{reviewer}:{round_id}"),
                "criteria": responses,
            }
        )
    return {
        "schema": ROUND_SCHEMA,
        "round_id": round_id,
        "contract_sha256": contract_digest,
        "candidate_sha256": _hash(candidate),
        "reviews": reviews,
    }


def _evaluate(
    tmp_path: Path,
    contract: dict,
    round_value: dict,
    name: str = "receipt.json",
    **kwargs,
):
    _write_json(tmp_path, "contract.json", contract)
    _write_json(tmp_path, "round.json", round_value)
    return evaluate_review_round(
        tmp_path,
        "contract.json",
        "round.json",
        name,
        **kwargs,
    )


def test_complete_review_is_advisory_and_binds_exact_coverage(tmp_path: Path) -> None:
    contract = _contract()
    result = _evaluate(tmp_path, contract, _round(contract))

    assert result["schema"] == RECEIPT_SCHEMA
    assert result["state"] == "REVIEW_COMPLETE_ADVISORY"
    assert len(result["coverage"]) == 4
    assert all(cell["state"] == "complete" for cell in result["coverage"])
    assert result["provenance_unverified"] is True
    assert not any(result["authority"].values())
    stored = json.loads((tmp_path / "receipt.json").read_text(encoding="utf-8"))
    claimed = stored.pop("receipt_sha256")
    assert (
        claimed
        == hashlib.sha256(
            json.dumps(
                stored, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
    )


def test_deduplicates_reviewers_without_weakening_required_finding(
    tmp_path: Path,
) -> None:
    contract = _contract()
    round_value = _round(
        contract,
        finding=_finding(priority=3),
    )
    round_value["reviews"][1]["criteria"][0]["findings"][0]["priority"] = 1
    result = _evaluate(tmp_path, contract, round_value)

    assert result["state"] == "REVIEW_FINDINGS"
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["reviewers"] == ["reviewer-a", "reviewer-b"]
    assert len(finding["evidence_sha256s"]) == 2
    assert finding["priority"] == 1
    assert finding["queue"] == "human_review"
    assert finding["disposition"] == "reported_unresolved"


@pytest.mark.parametrize(
    "mutation",
    ["missing_reviewer", "duplicate_cell", "unknown_outcome", "malformed_priority"],
)
def test_missing_duplicated_unknown_or_malformed_cells_are_indeterminate(
    tmp_path: Path, mutation: str
) -> None:
    contract = _contract()
    round_value = _round(contract)
    if mutation == "missing_reviewer":
        round_value["reviews"].pop()
    elif mutation == "duplicate_cell":
        response = round_value["reviews"][0]["criteria"][0]
        round_value["reviews"][0]["criteria"].append(response.copy())
    elif mutation == "unknown_outcome":
        round_value["reviews"][0]["criteria"][0]["outcome"] = "maybe"
    else:
        response = round_value["reviews"][0]["criteria"][0]
        response["outcome"] = "finding"
        response["findings"] = [_finding(priority=[])]

    result = _evaluate(tmp_path, contract, round_value)
    assert result["state"] == "INDETERMINATE"
    assert result["incomplete_cells"]
    assert "code correctness" in result["claim_boundary"]


def test_disagreeing_objective_alignment_escalates_to_human_queue(
    tmp_path: Path,
) -> None:
    contract = _contract()
    round_value = _round(contract, finding=_finding(alignment="required_by_objective"))
    round_value["reviews"][1]["criteria"][0]["findings"][0]["alignment"] = (
        "consistent_with_objective"
    )
    result = _evaluate(tmp_path, contract, round_value)

    assert result["findings"][0]["alignment"] == "unknown"
    assert result["findings"][0]["queue"] == "human_review"


def test_tracks_new_no_longer_reported_and_reopened_findings(tmp_path: Path) -> None:
    contract = _contract(reviewers=("reviewer-a",))
    first = _evaluate(
        tmp_path, contract, _round(contract, finding=_finding()), "first.json"
    )
    assert first["review_delta"]["state"] == "no_baseline"
    finding_id = first["findings"][0]["finding_id"]

    clean = _round(contract, round_id="round-2", candidate="candidate-2")
    _write_json(tmp_path, "round.json", clean)
    second = evaluate_review_round(
        tmp_path,
        "contract.json",
        "round.json",
        "second.json",
        previous_path="first.json",
    )
    assert second["review_delta"]["no_longer_reported"] == [finding_id]
    assert second["state"] == "REVIEW_COMPLETE_ADVISORY"

    reopened = _round(
        contract, finding=_finding(), round_id="round-3", candidate="candidate-3"
    )
    _write_json(tmp_path, "round.json", reopened)
    third = evaluate_review_round(
        tmp_path,
        "contract.json",
        "round.json",
        "third.json",
        previous_path="second.json",
    )
    assert third["review_delta"]["reopened"] == [finding_id]


def test_rejects_prior_contract_drift_and_tampering(tmp_path: Path) -> None:
    contract = _contract(reviewers=("reviewer-a",))
    _evaluate(tmp_path, contract, _round(contract), "prior.json")
    changed = _contract(reviewers=("reviewer-a",))
    changed["criteria"][0]["statement_sha256"] = _hash("changed obligation")
    round_value = _round(changed)
    _write_json(tmp_path, "contract.json", changed)
    _write_json(tmp_path, "round.json", round_value)
    with pytest.raises(ReviewConvergenceError, match="different review contract"):
        evaluate_review_round(
            tmp_path,
            "contract.json",
            "round.json",
            "changed.json",
            previous_path="prior.json",
        )

    stored_prior = json.loads((tmp_path / "prior.json").read_text(encoding="utf-8"))
    (tmp_path / "prior.json").write_text(
        json.dumps({**stored_prior, "state": "tampered"}), encoding="utf-8"
    )
    with pytest.raises(ReviewConvergenceError, match="self-hash"):
        evaluate_review_round(
            tmp_path,
            "contract.json",
            "round.json",
            "tampered.json",
            previous_path="prior.json",
        )


def test_rejects_path_escape_and_source_overwrite(tmp_path: Path) -> None:
    contract = _contract()
    round_value = _round(contract)
    _write_json(tmp_path, "contract.json", contract)
    _write_json(tmp_path, "round.json", round_value)
    with pytest.raises(ReviewConvergenceError, match="escapes"):
        evaluate_review_round(
            tmp_path, "../contract.json", "round.json", "receipt.json"
        )
    with pytest.raises(ReviewConvergenceError, match="must not overwrite"):
        evaluate_review_round(tmp_path, "contract.json", "round.json", "contract.json")


def test_duplicate_json_fields_are_rejected(tmp_path: Path) -> None:
    (tmp_path / "contract.json").write_text(
        '{"schema":"a","schema":"b"}', encoding="utf-8"
    )
    with pytest.raises(ReviewConvergenceError, match="duplicate JSON field"):
        evaluate_review_round(tmp_path, "contract.json", "round.json", "receipt.json")


def test_unrecognized_cell_shape_cannot_be_hidden_by_complete_cells(
    tmp_path: Path,
) -> None:
    contract = _contract(reviewers=("reviewer-a",))
    payload = _round(contract)
    payload["reviews"][0]["criteria"].append({"criterion_id": "authz", "extra": True})
    receipt = _evaluate(tmp_path, contract, payload)
    assert receipt["state"] == "INDETERMINATE"
    assert all(
        cell["reason"] == "criterion_record_invalid" for cell in receipt["coverage"]
    )


def test_unknown_criterion_rejects_entire_envelope(tmp_path: Path) -> None:
    contract = _contract(reviewers=("reviewer-a",))
    payload = _round(contract)
    payload["reviews"][0]["criteria"][0]["criterion_id"] = "unknown"
    with pytest.raises(ReviewConvergenceError, match="unknown criterion"):
        _evaluate(tmp_path, contract, payload)
    assert not (tmp_path / "receipt.json").exists()


def test_cli_writes_explicit_receipt_and_does_not_fail_ci_on_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    contract = _contract()
    _write_json(tmp_path, "contract.json", contract)
    _write_json(tmp_path, "round.json", _round(contract, finding=_finding()))

    code = main(
        [
            "audit",
            "convergence",
            "--root",
            str(tmp_path),
            "--contract",
            "contract.json",
            "--round",
            "round.json",
            "--out",
            "receipt.json",
            "--json",
        ]
    )

    assert code == 0
    assert (tmp_path / "receipt.json").is_file()
    assert json.loads(capsys.readouterr().out)["state"] == "REVIEW_FINDINGS"

    handoff_code = main(
        [
            "audit",
            "convergence",
            "--root",
            str(tmp_path),
            "--contract",
            "contract.json",
            "--round",
            "round.json",
            "--out",
            "a2a-cli-receipt.json",
            "--a2a",
        ]
    )
    handoff = json.loads(capsys.readouterr().out)
    assert handoff_code == 0
    assert handoff["role"] == "ROLE_USER"
    assert handoff["parts"][0]["data"]["schema"] == "factory.a2a.review-handoff.v1"


def test_a2a_message_round_trip_preserves_declared_identity_and_handoff(
    tmp_path: Path,
) -> None:
    contract = _contract(reviewers=("agent-reviewer",))
    round_value = _round(contract)
    message = {
        "messageId": "agent-turn-17",
        "contextId": "context-payment-review",
        "taskId": "task-payment-review",
        "role": "ROLE_AGENT",
        "parts": [
            {
                "data": round_value,
                "mediaType": "application/vnd.code-factory.review-round+json",
            }
        ],
    }
    result = _evaluate(tmp_path, contract, message, "a2a-receipt.json")

    assert result["state"] == "REVIEW_COMPLETE_ADVISORY"
    assert result["round_transport"] == {
        "kind": "a2a_message",
        "protocol_version": "1.0.0",
        "a2a_message_id": "agent-turn-17",
        "context_id": "context-payment-review",
        "task_id": "task-payment-review",
        "role_declared": "ROLE_AGENT",
        "sender_identity_verified": False,
    }
    outgoing = result["a2a_message"]
    assert outgoing["role"] == "ROLE_USER"
    assert outgoing["contextId"] == "context-payment-review"
    assert outgoing["taskId"] == "task-payment-review"
    assert (
        outgoing["parts"][0]["mediaType"]
        == "application/vnd.code-factory.review-handoff+json"
    )
    assert (
        outgoing["parts"][0]["data"]["expected_reply"]["schema"]
        == "factory.atomic-review-submission.v1"
    )
    assert outgoing["parts"][0]["data"]["authority"]["approval"] is False

    submission = {
        "schema": "factory.atomic-review-submission.v1",
        "round_id": "round-2",
        "contract_sha256": result["contract_sha256"],
        "candidate_sha256": _hash("candidate-2"),
        "review": {
            "reviewer_id": "agent-reviewer",
            "evidence_sha256": _hash("follow-up-evidence"),
            "criteria": [
                {"criterion_id": item["id"], "outcome": "supported", "findings": []}
                for item in contract["criteria"]
            ],
        },
    }
    reply = {
        "messageId": "agent-turn-18",
        "contextId": outgoing["contextId"],
        "taskId": outgoing["taskId"],
        "role": "ROLE_AGENT",
        "parts": [
            {
                "data": submission,
                "mediaType": "application/vnd.code-factory.review-round+json",
            }
        ],
    }
    resumed = _evaluate(
        tmp_path,
        contract,
        reply,
        "a2a-receipt-2.json",
        previous_path="a2a-receipt.json",
    )
    assert resumed["state"] == "REVIEW_COMPLETE_ADVISORY"
    assert resumed["round_transport"]["context_id"] == outgoing["contextId"]
    assert resumed["round_transport"]["task_id"] == outgoing["taskId"]
    assert (
        resumed["a2a_message"]["parts"][0]["data"]["reply_to"]["message_id"]
        == "agent-turn-18"
    )


def test_mcp_reads_convergence_and_exports_a2a_without_writing(tmp_path: Path) -> None:
    contract = _contract(reviewers=("reviewer-a",))
    _write_json(tmp_path, "contract.json", contract)
    _write_json(tmp_path, "round.json", _round(contract, finding=_finding()))
    evaluate_review_round(
        tmp_path,
        "contract.json",
        "round.json",
        ".factory/review-convergence/latest.json",
    )
    before = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "factory.audit_convergence_status",
                "arguments": {
                    "receipt": ".factory/review-convergence/latest.json",
                    "includeA2aMessage": True,
                },
            },
        },
        tmp_path,
    )
    content = json.loads(response["result"]["content"][0]["text"])
    default_response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "factory.audit_convergence_status",
                "arguments": {},
            },
        },
        tmp_path,
    )
    default_content = json.loads(default_response["result"]["content"][0]["text"])
    after = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    assert content["marker"] == "REVIEW_CONVERGENCE_MCP_READ_ONLY"
    assert content["status"]["state"] == "REVIEW_FINDINGS"
    assert content["status"]["a2a_message"]["role"] == "ROLE_USER"
    assert (
        content["status"]["a2a_handoff"]["message_id"]
        == content["status"]["a2a_message"]["messageId"]
    )
    assert content["status"]["findings"]["human_review"] == 1
    assert content["status"]["authority"]["approval"] is False
    assert (
        default_content["status"]["receipt_sha256"]
        == content["status"]["receipt_sha256"]
    )
    assert before == after


def test_graph_ops_reads_conventional_latest_receipt(tmp_path: Path) -> None:
    from factoryline.graph_ops import graph_ops_snapshot

    contract = _contract(reviewers=("reviewer-a",))
    _write_json(tmp_path, "contract.json", contract)
    _write_json(tmp_path, "round.json", _round(contract))
    evaluate_review_round(
        tmp_path,
        "contract.json",
        "round.json",
        ".factory/review-convergence/latest.json",
    )

    snapshot = graph_ops_snapshot(tmp_path)
    assert snapshot["review_convergence"]["state"] == "REVIEW_COMPLETE_ADVISORY"
    assert snapshot["review_convergence"]["latest"]["receipt_sha256"]
    assert snapshot["review_convergence"]["latest"]["a2a_handoff"]["available"] is True
    assert all(
        value is False for value in snapshot["review_convergence"]["authority"].values()
    )


def test_audit_convergence_engine_is_lazy_in_cli_process() -> None:
    check = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import factoryline.cli; "
            "assert 'factoryline.atomic_review_audit' not in sys.modules",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stderr


def test_ci_exports_optional_convergence_without_promoting_it_to_a_gate() -> None:
    workflow = (
        Path(__file__).parents[1]
        / ".github"
        / "workflows"
        / "factory-pr-proof-review.yml"
    ).read_text(encoding="utf-8")
    assert "Compile optional advisory review-convergence and A2A handoff" in workflow
    assert "factory audit convergence --root ." in workflow
    assert "NOT_CONFIGURED" in workflow
    assert "UNAVAILABLE_ADVISORY" in workflow
    assert "does not change the main FactoryLine Check" in workflow


@pytest.mark.parametrize("mode", ["valid", "missing", "invalid"])
def test_ci_convergence_executes_without_changing_main_proof(
    tmp_path: Path, mode: str
) -> None:
    root = Path(__file__).resolve().parents[1]
    git = shutil.which("git")
    bash = (
        str(Path(git).resolve().parents[1] / "bin" / "bash.exe")
        if sys.platform == "win32" and git
        else shutil.which("bash")
    )
    if not bash or not Path(bash).is_file():
        pytest.skip("Git Bash or Bash required for the workflow shell check")
    workflow = yaml.safe_load(
        (root / ".github/workflows/factory-pr-proof-review.yml").read_text(
            encoding="utf-8"
        )
    )
    step = next(
        step
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if step.get("name", "").startswith("Compile optional advisory")
    )
    baseline = tmp_path / "github-proof-review.json"
    baseline.write_bytes(b'{"check":{"conclusion":"neutral"}}')
    inputs = tmp_path / ".factory" / "review-convergence"
    inputs.mkdir(parents=True)
    if mode != "missing":
        contract = _contract()
        _write_json(inputs, "contract.json", contract)
        _write_json(
            inputs,
            "round.json",
            _round(contract) if mode == "valid" else {"invalid": True},
        )
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-s"],
        cwd=tmp_path,
        input='factory() { "$CF_TEST_PYTHON" -m factoryline.cli "$@"; }\n'
        + step["run"],
        env={
            **os.environ,
            "CF_TEST_PYTHON": Path(sys.executable).as_posix(),
            "PYTHONPATH": str(root),
        },
        encoding="utf-8",
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    output = tmp_path / ".factory/github-proof-review"
    report = json.loads(
        (output / "review-convergence.json").read_text(encoding="utf-8")
    )
    assert (
        report["state"]
        == {
            "valid": "REVIEW_COMPLETE_ADVISORY",
            "missing": "NOT_CONFIGURED",
            "invalid": "UNAVAILABLE_ADVISORY",
        }[mode]
    )
    assert (output / "review-convergence-receipt.json").is_file() == (mode == "valid")
    assert baseline.read_bytes() == b'{"check":{"conclusion":"neutral"}}'


@pytest.mark.parametrize(
    "field,bad_value",
    [("coverage", [None]), ("review_delta", []), ("required_reviewers", None)],
)
def test_rehashed_malformed_receipt_is_rejected(
    tmp_path: Path, field: str, bad_value: object
) -> None:
    contract = _contract(reviewers=("reviewer-a",))
    _evaluate(tmp_path, contract, _round(contract))
    receipt = json.loads((tmp_path / "receipt.json").read_text(encoding="utf-8"))
    receipt[field] = bad_value
    receipt.pop("receipt_sha256")
    receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(
            receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    _write_json(tmp_path, "receipt.json", receipt)
    with pytest.raises(ReviewConvergenceError, match="summary fields"):
        read_convergence_receipt(tmp_path, "receipt.json")


def test_agent_message_requires_context_and_replay_is_deterministic(
    tmp_path: Path,
) -> None:
    contract = _contract(reviewers=("reviewer-a",))
    message = {
        "messageId": "review-turn",
        "role": "ROLE_AGENT",
        "parts": [{"data": _round(contract)}],
    }
    with pytest.raises(ReviewConvergenceError, match="requires contextId"):
        _evaluate(tmp_path, contract, message)
    message["contextId"] = "review-context"
    first = _evaluate(tmp_path, contract, message)
    second = _evaluate(tmp_path, contract, message)
    assert first["receipt_sha256"] == second["receipt_sha256"]
    assert first["a2a_message"] == second["a2a_message"]
