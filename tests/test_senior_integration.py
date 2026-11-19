from datetime import datetime, timedelta, timezone
import hashlib
import pytest

from factoryline.benchmark_lab import evaluate_benchmark
from factoryline.independent_execution import validate_execution_attestation
from factoryline.incremental_scheduler import plan_incremental


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


@pytest.mark.parametrize("path", ["web/app.tsx", "server/app.go", "core/app.rs"])
def test_polyglot_sarif_handoff_and_existing_graph_chain_preserve_source(
    tmp_path, path
):
    """Synthetic SARIF conversion, not native detector or signer qualification."""
    from test_deep_audit_sarif import report, ANALYZER
    from factoryline.deep_audit_sarif import normalize_sarif
    from factoryline.deep_audit_io import canonical_bytes, sha256_bytes
    from factoryline.deep_audit import _agent_actions
    from factoryline.deep_audit_loop import _chain
    from factoryline.audit_action_refs import audit_remediation_packet

    payload = report()
    raw = canonical_bytes(payload).replace(b"app.py", path.encode())
    (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / path).write_bytes(b"source\nsink\n")
    (tmp_path / "report.json").write_bytes(raw)
    source_sha = sha256_bytes((tmp_path / path).read_bytes())
    finding = normalize_sarif(
        tmp_path,
        {"path": "report.json", "sha256": sha256_bytes(raw)},
        ANALYZER,
        {path: source_sha},
    )["findings"][0]
    action = _agent_actions("a" * 64, [finding])[0]
    assert action["finding_id"] == finding["finding_id"]
    assert action["affected_paths"] == [path]
    assert action["repair_packet"] == audit_remediation_packet("a" * 64, finding)
    assert action["repair_packet"]["automatic_execution"] is False
    chain = _chain(finding, {"decision": "REVIEW_REQUIRED"}, "report.json")
    assert (chain["finding_id"], chain["source"], chain["source_sha256"]) == (
        finding["finding_id"],
        path,
        source_sha,
    )
    assert chain["handoff"] == "human_review_required"


def test_receipts_are_bounded_and_cross_module_authority_stays_disabled(tmp_path):
    now = datetime.now(timezone.utc)
    attestation = {
        "schema": "factory.execution-attestation.v1",
        "attestation_id": "integration",
        "candidate_sha256": _digest("a"),
        "plan_sha256": _digest("b"),
        "run_nonce": "n",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "assurance_level": "hardened_vm",
        "runner": {
            "id": "runner",
            "version": "1",
            "platform": "windows",
            "backend": "hardened_vm",
            "executable_sha256": _digest("c"),
        },
        "observations": {
            "target_artifact_sha256": _digest("d"),
            "known_bad_artifact_sha256": _digest("e"),
            "target_stdout_sha256": None,
            "target_stderr_sha256": None,
            "cleanup_confirmed": True,
            "memory_peak_bytes": None,
            "latency_ms": 0,
        },
        "authority": "none",
    }
    assert validate_execution_attestation(attestation)["authority"] == "none"
    benchmark = {
        "schema": "factory.defect-benchmark.v1",
        "benchmark_id": "integration",
        "version": "1",
        "cases": [
            {
                "id": "case",
                "category": "performance_regression",
                "source": "fixtures/case",
                "source_sha256": _digest("f"),
                "expected_finding": "slow",
                "replay_argv": ["pytest", "tests/case.py"],
                "buggy_sha256": _digest("g"),
                "fixed_sha256": _digest("h"),
            }
        ],
    }
    receipt = evaluate_benchmark(
        benchmark,
        {
            "case": {
                "buggy": {"state": "FAIL", "finding": "slow"},
                "fixed": {"state": "PASS", "finding": ""},
            }
        },
    )
    assert receipt["authority"] == "none"
    schedule = {
        "schema": "factory.incremental-plan.v1",
        "plan_id": "integration",
        "assurance_level": "hardened_vm",
        "changed_paths": ["src/app.py"],
        "dependency_closure": {"check": ["src/app.py"]},
        "gates": [
            {"id": "check", "depends_on": [], "side_effects": False, "proof": None}
        ],
    }
    plan = plan_incremental(tmp_path, schedule)
    assert plan["release_approval"] is False
    assert all("authority" not in row for row in plan["items"])
