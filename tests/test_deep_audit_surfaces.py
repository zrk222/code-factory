import json
from pathlib import Path
import pytest
from test_deep_audit import inputs
from factoryline.cli import main
from factoryline.deep_audit import execute_deep_audit
from factoryline.mcp import _deep_audit_status, McpError, dispatch
from factoryline.mission_control_status import mission_control_status
from factoryline.ide_playbook import ide_playbook
from datetime import datetime, timedelta, timezone
from factoryline.deep_audit_attestation import (
    DeepAuditAttestationError,
    PAYLOAD_TYPE,
    SCHEMA,
    verify_deep_audit_attestation,
)
from factoryline.enterprise_receipts import generate_key_material, sign_payload
from factoryline.deep_audit_loop import compare_deep_audits
from copy import deepcopy
from factoryline.deep_audit import deep_audit_status
from factoryline.deep_audit_io import digest
from factoryline.deep_audit_loop import deep_audit_lineage
from factoryline.graph_ops import graph_ops_snapshot
import ast
from factoryline.intent_quality import bind_project_contracts


@pytest.mark.parametrize("clean", [False, True])
def test_cli_evaluates_signed_inputs_and_status(tmp_path, capsys, clean):
    args, _, _, _ = inputs(tmp_path, clean=clean)
    argv = [
        "deep-audit",
        "evaluate",
        "--plan",
        str(args[0]),
        "--trust-root",
        str(args[1]),
        "--trust-root-sha256",
        args[2],
        "--root",
        str(tmp_path),
    ]
    assert main(argv) == (0 if clean else 1)
    output = json.loads(capsys.readouterr().out)
    assert output["authority"] == "none"
    assert output["agent_actions"] == output["receipt"]["agent_actions"]
    assert main(["deep-audit", "status", "--root", str(tmp_path)]) == (
        0 if clean else 1
    )
    status = json.loads(capsys.readouterr().out)
    assert status["state"] == output["receipt"]["decision"]
    assert "agent_actions" in status


def test_no_evidence_is_not_a_green_cli(tmp_path, capsys):
    assert main(["deep-audit", "status", "--root", str(tmp_path)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["state"] == "NOT_RUN"
    assert report["agent_actions"]


@pytest.mark.parametrize("clean", [False, True])
def test_mission_and_mcp_preserve_review_boundary(tmp_path, clean):
    args, _, _, _ = inputs(tmp_path, clean=clean)
    execute_deep_audit(*args)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    mcp = _deep_audit_status(tmp_path, {})
    mission = mission_control_status(tmp_path)
    assert mission["evidence"]["deep_audit"] == mcp["status"]
    assert mission["state"] == ("review_required" if clean else "blocked")
    assert not any(mission["authority"].values())
    assert before == {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    with pytest.raises(McpError):
        _deep_audit_status(tmp_path, {"approve": True})


def test_tampering_blocks_mission(tmp_path):
    args, _, _, _ = inputs(tmp_path, clean=True)
    result = execute_deep_audit(*args)
    Path(result["receipt_path"]).write_text("{}")
    assert mission_control_status(tmp_path)["blockers"]["deep_audit_blocked"] == 1


def test_playbook_discovers_read_only_tool():
    assert "factory.deep_audit_status" in json.dumps(ide_playbook())


def test_mcp_dispatch_routes_to_read_only_status(tmp_path):
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "factory.deep_audit_status", "arguments": {}},
        },
        tmp_path,
    )
    body = json.loads(response["result"]["content"][0]["text"])
    assert body["marker"] == "DEEP_AUDIT_MCP_READ_ONLY"
    assert body["status"]["state"] == "NOT_RUN"
    assert not list(tmp_path.iterdir())


def test_execution_cli_inventory_and_read_only_mcp(tmp_path, capsys, monkeypatch):
    from test_deep_audit_contract import synthetic_execution

    args, result = synthetic_execution(tmp_path, monkeypatch)
    root = args[0]
    assert main(["deep-audit", "inventory", "--root", str(root), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "COMPLETE"
    assert (
        main(
            [
                "deep-audit",
                "progress",
                "--root",
                str(root),
                "--run-id",
                result["run_id"],
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["state"] == "INCOMPLETE"
    body = _deep_audit_status(root, {"run_id": result["run_id"]})
    assert body["status"]["state"] == "INCOMPLETE"
    assert body["repairs"]["review"] == "REQUIRED"
    with pytest.raises(McpError):
        _deep_audit_status(root, {"run_id": "../unsafe"})


# --- Merged from test_deep_audit_attestation.py; test definitions and fixtures retained ---


def _signed_attestation(
    root: Path,
    receipt_path: str,
    receipt: dict,
    *,
    issued: datetime | None = None,
    expires: datetime | None = None,
    **overrides,
):
    keys = generate_key_material(
        out_dir=root / "attestation-keys",
        keyid="independent-key",
        identity="verifier@example.test",
        issuer="https://verifier.example.test",
    )
    issued = issued or datetime.now(timezone.utc) - timedelta(seconds=2)
    expires = expires or issued + timedelta(hours=1)
    payload = {
        "schema": SCHEMA,
        "attestation_id": "independent-001",
        "receipt_sha256": receipt["receipt_sha256"],
        "plan_sha256": receipt["plan_sha256"],
        "candidate_sha256": receipt["candidate_sha256"],
        "ruleset_sha256": receipt["ruleset_sha256"],
        "canary_set_sha256": receipt["canary_set_sha256"],
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "verifier": {
            "id": "independent-verifier",
            "version": "1.0.0",
            "independent": True,
        },
        "observations": {
            "report_hashes": receipt["report_hashes"],
            "canary_hashes": receipt["canary_hashes"],
        },
        "authority": "none",
    }
    payload.update(overrides)
    envelope = sign_payload(
        payload,
        payload_type=PAYLOAD_TYPE,
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
    )
    path = root / "attestation.json"
    path.write_bytes(
        json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    return path, Path(keys["trust_root"]), payload


def _receipt(root: Path):
    args, _, _, _ = inputs(root, clean=True)
    result = execute_deep_audit(*args)
    return result["receipt"], Path(result["receipt_path"]).relative_to(root).as_posix()


def test_fresh_independent_attestation_verifies(tmp_path):
    receipt, receipt_path = _receipt(tmp_path)
    attestation, trust_root, _ = _signed_attestation(tmp_path, receipt_path, receipt)
    result = verify_deep_audit_attestation(
        tmp_path, attestation, trust_root, tmp_path / receipt_path
    )
    assert result["marker"] == "DEEP_AUDIT_ATTESTATION_VERIFIED"
    assert result["authority"] == "none"
    assert result["release_approval"] is False


@pytest.mark.parametrize(
    "issued_delta,expires_delta",
    [
        (
            timedelta(minutes=5),
            timedelta(hours=1),
        ),
        (
            -timedelta(hours=2),
            timedelta(hours=1),
        ),
    ],
)
def test_future_or_stale_attestation_fails_closed(
    tmp_path, issued_delta, expires_delta
):
    now = datetime.now(timezone.utc)
    issued, expires = now + issued_delta, now + expires_delta
    receipt, receipt_path = _receipt(tmp_path)
    attestation, trust_root, _ = _signed_attestation(
        tmp_path, receipt_path, receipt, issued=issued, expires=expires
    )
    with pytest.raises(DeepAuditAttestationError, match="E_DEEP_ATTESTATION_FRESHNESS"):
        verify_deep_audit_attestation(
            tmp_path, attestation, trust_root, tmp_path / receipt_path
        )


def test_attestation_validity_window_and_clock_policy_are_bounded(tmp_path):
    receipt, receipt_path = _receipt(tmp_path)
    issued = datetime.now(timezone.utc) - timedelta(seconds=2)
    attestation, trust_root, _ = _signed_attestation(
        tmp_path,
        receipt_path,
        receipt,
        issued=issued,
        expires=issued + timedelta(hours=25),
    )
    with pytest.raises(DeepAuditAttestationError, match="E_DEEP_ATTESTATION_FRESHNESS"):
        verify_deep_audit_attestation(
            tmp_path, attestation, trust_root, tmp_path / receipt_path
        )
    attestation, trust_root, _ = _signed_attestation(
        tmp_path,
        receipt_path,
        receipt,
        issued=issued,
        expires=issued + timedelta(hours=1),
    )
    with pytest.raises(DeepAuditAttestationError, match="E_DEEP_ATTESTATION_FRESHNESS"):
        verify_deep_audit_attestation(
            tmp_path,
            attestation,
            trust_root,
            tmp_path / receipt_path,
            max_age_seconds=0,
        )


def test_analyzer_self_attestation_and_coverage_mismatch_are_rejected(tmp_path):
    receipt, receipt_path = _receipt(tmp_path)
    attestation, trust_root, _ = _signed_attestation(
        tmp_path,
        receipt_path,
        receipt,
        verifier={"id": "s", "version": "1.0.0", "independent": True},
    )
    with pytest.raises(
        DeepAuditAttestationError, match="E_DEEP_ATTESTATION_INDEPENDENCE"
    ):
        verify_deep_audit_attestation(
            tmp_path, attestation, trust_root, tmp_path / receipt_path
        )
    attestation, trust_root, _ = _signed_attestation(
        tmp_path,
        receipt_path,
        receipt,
        observations={"report_hashes": {}, "canary_hashes": receipt["canary_hashes"]},
    )
    with pytest.raises(DeepAuditAttestationError, match="E_DEEP_ATTESTATION_BINDING"):
        verify_deep_audit_attestation(
            tmp_path, attestation, trust_root, tmp_path / receipt_path
        )


def test_signature_and_receipt_binding_fail_closed(tmp_path):
    receipt, receipt_path = _receipt(tmp_path)
    attestation, trust_root, payload = _signed_attestation(
        tmp_path, receipt_path, receipt
    )
    envelope = json.loads(attestation.read_text())
    envelope["signatures"][0]["sig"] = "AAAA"
    attestation.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(DeepAuditAttestationError, match="E_DEEP_ATTESTATION_SIGNATURE"):
        verify_deep_audit_attestation(
            tmp_path, attestation, trust_root, tmp_path / receipt_path
        )
    attestation, trust_root, _ = _signed_attestation(
        tmp_path, receipt_path, receipt, candidate_sha256="a" * 64
    )
    with pytest.raises(DeepAuditAttestationError, match="E_DEEP_ATTESTATION_BINDING"):
        verify_deep_audit_attestation(
            tmp_path, attestation, trust_root, tmp_path / receipt_path
        )


def test_strict_comparison_requires_and_reports_attestations(tmp_path):
    receipt, receipt_path = _receipt(tmp_path)
    missing = compare_deep_audits(
        tmp_path, receipt_path, receipt_path, require_attestation=True
    )
    assert missing["code"] == "E_DEEP_ATTESTATION_REQUIRED"
    attestation, trust_root, _ = _signed_attestation(tmp_path, receipt_path, receipt)
    result = compare_deep_audits(
        tmp_path,
        receipt_path,
        receipt_path,
        before_attestation=str(attestation),
        after_attestation=str(attestation),
        trust_root_path=trust_root,
        require_attestation=True,
    )
    assert result["state"] == "approval_required"
    assert result["verification"] == "offline_dsse_and_freshness"
    assert result["attestations"]["before"]["verifier"]["independent"] is True
    assert result["authority"] == "none"


def test_cli_attestation_returns_verified_receipt(tmp_path, capsys):
    receipt, receipt_path = _receipt(tmp_path)
    attestation, trust_root, _ = _signed_attestation(tmp_path, receipt_path, receipt)
    code = main(
        [
            "deep-audit",
            "attestation",
            "--root",
            str(tmp_path),
            str(attestation),
            "--receipt",
            receipt_path,
            "--trust-root",
            str(trust_root),
        ]
    )
    assert code == 0
    assert (
        json.loads(capsys.readouterr().out)["marker"]
        == "DEEP_AUDIT_ATTESTATION_VERIFIED"
    )


# --- Merged from test_deep_audit_loop.py; test definitions and fixtures retained ---


def write(root, receipt):
    body = deepcopy(receipt)
    body.pop("receipt_sha256", None)
    body["receipt_sha256"] = digest(body)
    path = root / ".factory" / "deep-audits" / (body["receipt_sha256"] + ".json")
    path.write_text(json.dumps(body), encoding="utf-8")
    return path.relative_to(root).as_posix()


def initial(root):
    args, _, _, _ = inputs(root)
    result = execute_deep_audit(*args)
    return result["receipt"], Path(result["receipt_path"]).relative_to(root).as_posix()


def test_same_receipt_stagnates_without_authority(tmp_path):
    _, path = initial(tmp_path)
    result = compare_deep_audits(tmp_path, path, path)
    assert result["state"] == "stagnated"
    assert result["authority"] == "none"


@pytest.mark.parametrize("key", ["ruleset_sha256", "canary_set_sha256"])
def test_changed_policy_blocks(tmp_path, key):
    receipt, path = initial(tmp_path)
    receipt[key] = "a" * 64
    result = compare_deep_audits(tmp_path, path, write(tmp_path, receipt))
    assert result["code"] == "E_DEEP_POLICY_CHANGED"


def test_lost_coverage_blocks(tmp_path):
    receipt, path = initial(tmp_path)
    receipt["report_hashes"] = {}
    assert (
        compare_deep_audits(tmp_path, path, write(tmp_path, receipt))["state"]
        == "blocked"
    )


def test_new_finding_and_new_blocker_regress(tmp_path):
    receipt, path = initial(tmp_path)
    added = deepcopy(receipt["findings"][0])
    added["finding_id"] = "b" * 64
    receipt["findings"].append(added)
    assert (
        compare_deep_audits(tmp_path, path, write(tmp_path, receipt))["state"]
        == "regressed"
    )
    receipt["findings"].pop()
    receipt["repair_queue"].append({"code": "DEEP_TRACE_INCOMPLETE"})
    assert (
        compare_deep_audits(tmp_path, path, write(tmp_path, receipt))["state"]
        == "regressed"
    )


def test_reduction_then_human_only_closure(tmp_path):
    receipt, _ = initial(tmp_path)
    added = deepcopy(receipt["findings"][0])
    added["finding_id"] = "b" * 64
    receipt["findings"].append(added)
    before = write(tmp_path, receipt)
    receipt["findings"].pop()
    assert (
        compare_deep_audits(tmp_path, before, write(tmp_path, receipt))["state"]
        == "repair_required"
    )
    receipt.update(findings=[], repair_queue=[], decision="READY_FOR_HUMAN_REVIEW")
    assert (
        compare_deep_audits(tmp_path, before, write(tmp_path, receipt))["state"]
        == "approval_required"
    )


def test_invalid_and_escaping_inputs_block(tmp_path):
    _, path = initial(tmp_path)
    assert compare_deep_audits(tmp_path, path, "../outside.json")["state"] == "blocked"
    (tmp_path / path).write_text("{}")
    assert compare_deep_audits(tmp_path, path, path)["state"] == "blocked"


def test_graph_has_six_non_authorizing_stages(tmp_path):
    initial(tmp_path)
    result = graph_ops_snapshot(tmp_path)
    nodes = [n for n in result["nodes"] if n["kind"].startswith("deep_audit_")]
    assert {n["kind"] for n in nodes} == {
        "deep_audit_" + k
        for k in ("source", "obligation", "finding", "evidence", "decision", "handoff")
    }
    assert all(n["status"] == "unassessed" for n in nodes)
    assert result["deep_audit"]["authority"] == "none"


def test_projection_bound_and_stale_observation(tmp_path):
    receipt, _ = initial(tmp_path)
    receipt["findings"] = [
        {**receipt["findings"][0], "finding_id": digest(i)} for i in range(51)
    ]
    write(tmp_path, receipt)
    status = deep_audit_status(tmp_path)
    result = deep_audit_lineage(tmp_path, status)
    assert len(result["chains"]) == 50 and result["truncated"]
    status["receipt_sha256"] = "a" * 64
    assert deep_audit_lineage(tmp_path, status)["state"] == "INCOMPLETE"


def test_compare_cli(tmp_path, capsys):
    _, path = initial(tmp_path)
    assert (
        main(
            [
                "deep-audit",
                "compare",
                "--root",
                str(tmp_path),
                "--before",
                path,
                "--after",
                path,
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["state"] == "stagnated"


def _traced_lane():
    trace = {
        "schema": "factory.zap-source-trace.normalized.v1",
        "run_id": "trace-run",
        "candidate_sha256": "c" * 64,
        "profile_sha256": "d" * 64,
        "target_sha256": "e" * 64,
        "provider": "python-stdlib-http.v1",
        "raw_sha256": "a" * 64,
        "observations": [
            {
                "route_id": "home",
                "path": "src/app.py",
                "source_sha256": "b" * 64,
                "lines": [5, 6],
            }
        ],
    }
    return {
        "lane_id": "runtime",
        "state": "INCOMPLETE",
        "findings": [],
        "gaps": ["ZAP_SOURCE_ROUTE_COVERAGE_REQUIRED"],
        "native_execution": {
            "source_trace": trace,
            "cleanup_confirmed": True,
            "candidate_replay": {"source_trace": deepcopy(trace)},
        },
    }


def test_run_details_retains_trace_observations_and_missing_bindings():
    from factoryline.deep_audit_loop import _run_details

    lane = _traced_lane()
    lane["native_execution"]["source_trace_missing"] = [
        {"route_id": "other", "path": "src/other.py"}
    ]
    value = _run_details({"lanes": [lane], "gaps": []})
    trace = value["lanes"][0]["source_trace"]
    assert trace["observations"][0]["lines"] == [5, 6]
    assert trace["missing_binding_count"] == 1
    assert trace["missing_bindings"] == [{"route_id": "other", "path": "src/other.py"}]
    assert trace["replay_matches"] is True and trace["cleanup_confirmed"] is True
    assert "not signed validation" in trace["claim_boundary"]
    assert value["lanes"][0]["state"] == "INCOMPLETE"


def test_trace_display_is_bounded_without_hiding_counts():
    from factoryline.deep_audit_loop import _source_trace_summary

    lane = _traced_lane()
    row = lane["native_execution"]["source_trace"]["observations"][0]
    row["lines"] = list(range(1, 151))
    lane["native_execution"]["source_trace"]["observations"] = [row] * 23
    trace = _source_trace_summary(lane)
    assert trace["observation_count"] == 23 and len(trace["observations"]) == 20
    assert trace["observations"][0]["line_count"] == 150
    assert len(trace["observations"][0]["lines"]) == 100
    assert trace["truncated"] is True and trace["replay_matches"] is False


@pytest.mark.parametrize(
    "path", ["/private/app.py", "../app.py", "C:/private/app.py", "src\\app.py"]
)
def test_trace_projection_rejects_noncanonical_paths(path):
    from factoryline.deep_audit_loop import _source_trace_summary

    lane = _traced_lane()
    lane["native_execution"]["source_trace"]["observations"][0]["path"] = path
    with pytest.raises(ValueError, match="source-trace path"):
        _source_trace_summary(lane)


def test_trace_error_remains_visible_without_invented_observations():
    from factoryline.deep_audit_loop import _source_trace_summary

    trace = _source_trace_summary(
        {"native_execution": {"source_trace_error": "E_TRACE_CAPTURE"}}
    )
    assert trace["error"] == "E_TRACE_CAPTURE"
    assert trace["observations"] == [] and trace["replay_matches"] is False
    assert trace["cleanup_confirmed"] is False
    assert _source_trace_summary({}) is None


@pytest.mark.parametrize(
    "key",
    [
        "schema",
        "run_id",
        "candidate_sha256",
        "profile_sha256",
        "target_sha256",
        "provider",
    ],
)
def test_trace_projection_never_matches_replay_with_changed_identity(key):
    from factoryline.deep_audit_loop import _source_trace_summary

    lane = _traced_lane()
    lane["native_execution"]["candidate_replay"]["source_trace"][key] = "different"
    assert _source_trace_summary(lane)["replay_matches"] is False


# --- Merged from test_implementation_audit_contracts.py; test definitions and fixtures retained ---
"""Focused tests for local implementation-contract binding."""


def _bind(root, base_source, implementation_source, *, write_base=True):
    base, implementation = root / "base.py", root / "impl.py"
    if write_base:
        base.write_text(base_source, encoding="utf-8")
    implementation.write_text(implementation_source, encoding="utf-8")
    snapshots = {
        base: ast.parse(base_source),
        implementation: ast.parse(implementation_source),
    }
    contexts = {path: {} for path in snapshots}
    edges = []
    bind_project_contracts(root, snapshots, contexts, edges)
    return contexts, edges


def test_missing_imported_source_does_not_create_implementation_contract(tmp_path):
    contexts, edges = _bind(
        tmp_path,
        "class Adapter:\n    def run(self):\n        raise NotImplementedError\n",
        "from base import Adapter\n"
        "class Concrete(Adapter):\n    def run(self):\n        return 1\n",
        write_base=False,
    )

    assert not contexts[tmp_path / "base.py"].get("implementation_contract_lines")
    assert edges == []


def test_imported_symbol_mismatch_does_not_create_contract_edge(tmp_path):
    contexts, edges = _bind(
        tmp_path,
        "class RenamedAdapter:\n    def run(self):\n        raise NotImplementedError\n",
        "from base import Adapter\n"
        "class Concrete(Adapter):\n    def run(self):\n        return 1\n",
    )

    assert not contexts[tmp_path / "base.py"].get("implementation_contract_lines")
    assert edges == []
