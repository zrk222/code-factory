from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.analysis_evidence import (
    AnalysisEvidenceError,
    assess_review_reuse,
    build_execution_review_evidence,
    build_review_evidence,
    parse_analysis_sarif,
    validate_review_evidence,
)


def _sarif(root: Path, tool: str, *, result: dict[str, object] | None = None) -> Path:
    path = root / f"{tool.casefold()}.sarif.json"
    path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": tool}},
                        "invocations": [{"executionSuccessful": True}],
                        "results": [result] if result else [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    ("tool", "provider"),
    [("JetBrains Qodana", "qodana"), ("SonarQube for IDE", "sonarqube")],
)
def test_adapter_auto_detects_supported_analyzers_and_binds_exact_bytes(
    tmp_path: Path, tool: str, provider: str
) -> None:
    path = _sarif(
        tmp_path,
        tool,
        result={
            "ruleId": "quality:one",
            "level": "warning",
            "baselineState": "new",
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}}}
            ],
        },
    )
    result = parse_analysis_sarif(tmp_path, path)
    assert result["provider"] == provider
    assert result["execution_successful"] is True
    assert result["counts"]["new"] == 1
    assert result["findings"][0]["paths"] == ["src/app.py"]
    assert len(result["file_sha256"]) == len(result["evidence_sha256"]) == 64
    assert all(value is False for value in result["authority"].values())


def test_adapter_rejects_unknown_ambiguous_and_mismatched_providers(
    tmp_path: Path,
) -> None:
    unknown = _sarif(tmp_path, "Unknown Analyzer")
    with pytest.raises(AnalysisEvidenceError, match="auto detection") as auto_error:
        parse_analysis_sarif(tmp_path, unknown)
    assert auto_error.value.code == "ANALYSIS_PROVIDER_UNVERIFIED"

    qodana = _sarif(tmp_path, "JetBrains Qodana")
    with pytest.raises(AnalysisEvidenceError, match="requested sonarqube") as mismatch:
        parse_analysis_sarif(tmp_path, qodana, provider="sonarqube")
    assert mismatch.value.code == "ANALYSIS_PROVIDER_MISMATCH"

    ambiguous = _sarif(tmp_path, "Qodana SonarQube Bridge")
    with pytest.raises(AnalysisEvidenceError, match="more than one") as ambiguous_error:
        parse_analysis_sarif(tmp_path, ambiguous)
    assert ambiguous_error.value.code == "ANALYSIS_PROVIDER_AMBIGUOUS"


def test_adapter_drops_unsafe_location_uris_but_keeps_the_finding(
    tmp_path: Path,
) -> None:
    path = _sarif(
        tmp_path,
        "SonarQube",
        result={
            "ruleId": "security:path",
            "level": "error",
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "../secret.txt"}}},
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "file:///tmp/secret.txt"}
                    }
                },
            ],
        },
    )
    result = parse_analysis_sarif(tmp_path, path)
    assert result["findings"][0]["paths"] == []
    assert result["counts"]["unbaselined"] == 1


def test_review_evidence_packet_keeps_unknowns_and_validates_hashes() -> None:
    from hashlib import sha256
    import json

    def seal(value: dict[str, object]) -> str:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return sha256(raw).hexdigest()

    receipt: dict[str, object] = {
        "candidate_sha256": "a" * 64,
        "findings": [
            {
                "finding_id": "finding-1",
                "analyzer_id": "codeql",
                "rule_id": "security:path",
                "locations": [{"path": "src/app.py"}],
            }
        ],
        "report_hashes": {"codeql": "b" * 64},
    }
    receipt["receipt_sha256"] = seal(receipt)
    packet = build_review_evidence(receipt)
    assert validate_review_evidence(packet) == packet
    assert packet["claims"][0]["supporting_evidence_ids"]
    assert packet["claims"][0]["contradicting_evidence_ids"] == []
    assert any(
        "candidate source hashes" in item["verification_action"]
        for item in packet["unknowns"]
    )
    assert any(
        "runtime evidence" in item["verification_action"] for item in packet["unknowns"]
    )
    evidence_id = packet["evidence"][0]["id"]
    assert (
        assess_review_reuse(
            packet,
            candidate_sha256="a" * 64,
            receipt_sha256=receipt["receipt_sha256"],
            required_evidence_ids=[evidence_id],
        )["decision"]
        == "REUSE"
    )
    assert (
        assess_review_reuse(
            packet,
            candidate_sha256="c" * 64,
            receipt_sha256=receipt["receipt_sha256"],
            required_evidence_ids=[evidence_id],
        )["decision"]
        == "RERUN"
    )
    assert (
        assess_review_reuse(
            packet,
            candidate_sha256="a" * 64,
            receipt_sha256=receipt["receipt_sha256"],
            required_evidence_ids=["missing"],
        )["decision"]
        == "RERUN"
    )

    tampered = dict(packet)
    tampered["candidate_sha256"] = "c" * 64
    with pytest.raises(AnalysisEvidenceError, match="packet hash"):
        validate_review_evidence(tampered)


def test_review_evidence_rejects_source_receipt_hash_mismatch() -> None:
    from hashlib import sha256

    receipt = {
        "candidate_sha256": "a" * 64,
        "findings": [],
        "report_hashes": {"codeql": "invalid"},
    }
    receipt["receipt_sha256"] = sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(AnalysisEvidenceError, match="report hash"):
        build_review_evidence(receipt)


def test_review_evidence_rejects_report_body_mismatch() -> None:
    from hashlib import sha256

    receipt = {
        "candidate_sha256": "a" * 64,
        "findings": [],
        "report_hashes": {"codeql": "b" * 64},
    }
    receipt["receipt_sha256"] = sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    report = {
        "analyzer": {"id": "codeql"},
        "execution_successful": True,
        "normalized_sha256": "b" * 64,
    }
    with pytest.raises(AnalysisEvidenceError, match="normalized report"):
        build_review_evidence(receipt, reports=[report])


def test_execution_packet_binds_persisted_six_lane_evidence(tmp_path: Path) -> None:
    import hashlib

    candidate = "a" * 64
    lanes = []
    plan_lanes = []
    for index in range(6):
        lane_id = f"lane-{index}"
        engine = f"engine-{index}"
        plan_lanes.append({"id": lane_id, "engine": engine})
        lanes.append(
            {
                "lane_id": lane_id,
                "engine": engine,
                "family": "runtime" if index == 0 else "static",
                "state": "OBSERVED",
                "gaps": [],
                "report_sha256": str(index) * 64,
                "coverage_sha256": str(index + 1) * 64,
                "findings": (
                    [
                        {
                            "rule_id": "R1",
                            "kind": "fail",
                            "level": "warning",
                            "locations": [
                                {"path": "src/app.py", "source_sha256": "f" * 64}
                            ],
                            "flows": [],
                        }
                    ]
                    if index == 0
                    else []
                ),
            }
        )
    state = {
        "candidate_sha256": candidate,
        "run_id": "run-1",
        "lanes": lanes,
        "findings": [],
    }
    canonical = json.dumps(
        state,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    state_file = tmp_path / "evidence.json"
    state_file.write_bytes(
        json.dumps(
            {**state, "sha256": hashlib.sha256(canonical).hexdigest()},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    )
    packet = build_execution_review_evidence(state, {"lanes": plan_lanes}, state_file)
    assert validate_review_evidence(packet) == packet
    assert (
        len([item for item in packet["evidence"] if item["kind"] == "lane_observation"])
        == 6
    )
    assert len(packet["claims"]) == 1
    assert "not a confirmed defect" in packet["claims"][0]["statement"]
    assert any(
        item["id"].startswith("runtime_evidence:") for item in packet["unknowns"]
    )
    state_file.write_text("{}", encoding="utf-8")
    with pytest.raises(AnalysisEvidenceError, match="does not match returned state"):
        build_execution_review_evidence(state, {"lanes": plan_lanes}, state_file)
