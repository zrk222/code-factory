import copy
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_advisory_recall as recall  # noqa: E402

RECORD = ROOT / "docs/evidence/advisory-recall-factory-20261121.json"


@pytest.fixture(scope="module")
def record():
    return json.loads(RECORD.read_text(encoding="utf-8"))


def test_record_recomputes_lane_separated_summary(record):
    summary = recall.verify(record)
    assert summary["total"] == {
        "cases": 161,
        "pattern_detected": 6,
        "codeql_detected": 15,
        "combined_detected": 20,
        "overlap": 1,
        "codeql_analyzed": 91,
        "codeql_state_extraction_failed": 10,
        "codeql_state_no_class_query": 2,
        "codeql_state_not_run": 33,
        "codeql_state_no_extractor": 25,
    }
    assert summary["codeql_untuned"]["wilson_95_over_analyzed"] == [0.102513, 0.254309]
    assert "wilson_95_descriptive_only" in summary["combined_not_held_out"]
    assert "NOT held out" in record["claim"]
    assert record["exposure"]["pattern"].startswith("Exposed")


def test_record_binds_revisions_files_and_tools(record):
    candidate = record["candidate"]
    assert candidate["measured_commit"].startswith("dd6fc8ab")
    assert (
        candidate["pattern_lane"]["ruleset_sha256"]
        == json.loads(
            (
                ROOT / "deploy/deep-adapters/profiles/semgrep-pattern-limited.json"
            ).read_text()
        )["ruleset_sha256"]
    )
    assert candidate["codeql_lane"]["cli_version"] == "2.27.1"
    assert all(case["fixes"] and case["prefix_files"] for case in record["cases"])
    detections = [
        hit for case in record["cases"] for hit in case["pattern"]["detections"]
    ]
    assert {hit["rule"] for hit in detections} == {
        "java.disabled-hostname-verification",
        "ruby.disabled-tls-verification",
    }


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda case: case["codeql"]["detections"][0].update(line=10**6),
            "outside the fix hunks",
        ),
        (lambda case: case["codeql"].update(source_revision="0" * 40), "first parent"),
        (lambda case: case["codeql"].update(status="not_detected"), "disagrees"),
        (
            lambda case: case["prefix_files"][0].update(sha256="x"),
            "unbound pre-fix file",
        ),
    ],
)
def test_record_rejects_altered_observations(record, mutate, message):
    altered = copy.deepcopy(record)
    case = next(
        case for case in altered["cases"] if case["codeql"]["status"] == "detected"
    )
    mutate(case)
    with pytest.raises(ValueError, match=message):
        recall.verify(altered)


def test_record_rejects_inflated_summary(record):
    altered = copy.deepcopy(record)
    altered["summary"]["total"]["combined_detected"] = 21
    with pytest.raises(ValueError, match="does not match"):
        recall.verify(altered)


def test_prefix_cache_digest_mismatch_is_rejected(record, tmp_path):
    case = next(case for case in record["cases"] if case["pattern"]["detections"])
    subset = dict(record, cases=[case])
    for item in case["prefix_files"]:
        target = recall._cache_path(tmp_path, case, item)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"not the pre-fix source")
    with pytest.raises(ValueError, match="pre-fix bytes differ"):
        recall.check_cache(subset, tmp_path)


def test_cli_reports_verified_record():
    assert recall.main([str(RECORD)]) == 0
