from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.analysis_evidence import AnalysisEvidenceError, parse_analysis_sarif


def _sarif(root: Path, tool: str, *, result: dict[str, object] | None = None) -> Path:
    path = root / f"{tool.casefold()}.sarif.json"
    path.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool}},
            "invocations": [{"executionSuccessful": True}],
            "results": [result] if result else [],
        }],
    }), encoding="utf-8")
    return path


@pytest.mark.parametrize(("tool", "provider"), [("JetBrains Qodana", "qodana"), ("SonarQube for IDE", "sonarqube")])
def test_adapter_auto_detects_supported_analyzers_and_binds_exact_bytes(tmp_path: Path, tool: str, provider: str) -> None:
    path = _sarif(tmp_path, tool, result={
        "ruleId": "quality:one",
        "level": "warning",
        "baselineState": "new",
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}}}],
    })
    result = parse_analysis_sarif(tmp_path, path)
    assert result["provider"] == provider
    assert result["execution_successful"] is True
    assert result["counts"]["new"] == 1
    assert result["findings"][0]["paths"] == ["src/app.py"]
    assert len(result["file_sha256"]) == len(result["evidence_sha256"]) == 64
    assert all(value is False for value in result["authority"].values())


def test_adapter_rejects_unknown_ambiguous_and_mismatched_providers(tmp_path: Path) -> None:
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


def test_adapter_drops_unsafe_location_uris_but_keeps_the_finding(tmp_path: Path) -> None:
    path = _sarif(tmp_path, "SonarQube", result={
        "ruleId": "security:path",
        "level": "error",
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "../secret.txt"}}},
            {"physicalLocation": {"artifactLocation": {"uri": "file:///tmp/secret.txt"}}},
        ],
    })
    result = parse_analysis_sarif(tmp_path, path)
    assert result["findings"][0]["paths"] == []
    assert result["counts"]["unbaselined"] == 1
