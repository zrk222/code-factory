import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import precision_review as review  # noqa: E402

RULES = """rules:
  - id: javascript.parameter-shell-command
    metadata:
      confidence: LOW
      cwe: ["CWE-78"]
  - id: python.unsafe-deserialization-unscoped
    metadata:
      confidence: HIGH
      cwe: ["CWE-502"]
"""


def test_wilson_matches_known_interval():
    assert review.wilson(25, 54) == [0.3369, 0.5939]
    assert review.wilson(0, 0) is None
    assert review.beta_mean(0, 0) == 0.5


def test_tiers_need_enough_decided_alerts_and_a_lower_bound():
    assert review.tier_for(19, 0) == "unqualified"
    assert review.tier_for(40, 1) == "default"
    assert review.tier_for(12, 8) == "review"
    assert review.tier_for(2, 18) == "retire"


def _alerts(tmp_path: Path) -> Path:
    source = tmp_path / "case" / "app.js"
    source.parent.mkdir()
    source.write_text("\n".join(f"line {n}" for n in range(1, 21)) + "\n")
    rows = [{"case": "GHSA-aaaa-bbbb-cccc", "root": str(tmp_path / "case"), "path": "app.js", "line": n,
             "rule": "javascript.parameter-shell-command", "on_fix_hunk": n == 3} for n in (3, 7, 9)]
    rows.append(dict(rows[0]))  # a duplicate report of the same alert
    path = tmp_path / "alerts.json"
    path.write_text(json.dumps(rows))
    return path


def test_packet_is_blinded_deduplicated_and_sealed(tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text(RULES)
    review.main(["packet", "--alerts", str(_alerts(tmp_path)), "--rules", str(rules), "--cohort", "t",
                 "--seed", "7", "--out", str(tmp_path / "p.json"), "--key", str(tmp_path / "k.json")])
    packet = json.loads((tmp_path / "p.json").read_text())
    key = json.loads((tmp_path / "k.json").read_text())
    assert len(packet["items"]) == 3
    assert all("rule" not in item and "on_fix_hunk" not in item for item in packet["items"])
    assert {item["claimed_weakness"] for item in packet["items"]} == {"command injection"}
    assert key["packet_sha256"] == review.sha256_bytes((tmp_path / "p.json").read_bytes())
    marked = [line for line in packet["items"][0]["context"].splitlines() if line[5] == ">"]
    assert len(marked) == 1


def _labels(packet: dict, verdicts: list[str], name: str, tmp_path: Path) -> Path:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps({"reviewer": name, "labels": [
        {"item": item["item"], "verdict": verdict, "reason": "r"} for item, verdict in zip(packet["items"], verdicts)]}))
    return path


def test_judge_and_adjudication_flow(tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text(RULES)
    review.main(["packet", "--alerts", str(_alerts(tmp_path)), "--rules", str(rules), "--cohort", "t",
                 "--seed", "7", "--out", str(tmp_path / "p.json"), "--key", str(tmp_path / "k.json")])
    packet = json.loads((tmp_path / "p.json").read_text())
    first = _labels(packet, ["TP", "FP", "TP"], "a", tmp_path)
    second = _labels(packet, ["TP", "UNCLEAR", "FP"], "b", tmp_path)
    review.main(["judge", "--packet", str(tmp_path / "p.json"), "--labels", str(first), str(second),
                 "--out", str(tmp_path / "j-in.json")])
    disagreements = json.loads((tmp_path / "j-in.json").read_text())["disagreements"]
    assert [row["position"] for row in disagreements] == [1, 2]
    (tmp_path / "j.json").write_text(json.dumps({"verdicts": [
        {"position": 1, "item": disagreements[0]["item"], "verdict": "FP"},
        {"position": 2, "item": disagreements[1]["item"], "verdict": "TP"}]}))
    review.main(["adjudicate", "--packet", str(tmp_path / "p.json"), "--key", str(tmp_path / "k.json"),
                 "--labels", str(first), str(second), "--reviewer", "a", "b", "--judge", str(tmp_path / "j.json"),
                 "--judge-name", "j", "--out", str(tmp_path / "adj.json")])
    adjudicated = json.loads((tmp_path / "adj.json").read_text())
    assert [row["final"] for row in adjudicated["rows"]] == ["TP", "FP", "TP"]
    review.main(["ledger", "--adjudicated", str(tmp_path / "adj.json"), "--out", str(tmp_path / "led.json")])
    entry = json.loads((tmp_path / "led.json").read_text())["rules"]["javascript.parameter-shell-command"]
    assert (entry["tp"], entry["fp"], entry["evidence_tier"]) == (2, 1, "unqualified")


def test_adjudication_refuses_unjudged_disagreement_and_foreign_key(tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text(RULES)
    review.main(["packet", "--alerts", str(_alerts(tmp_path)), "--rules", str(rules), "--cohort", "t",
                 "--seed", "7", "--out", str(tmp_path / "p.json"), "--key", str(tmp_path / "k.json")])
    packet = json.loads((tmp_path / "p.json").read_text())
    first = _labels(packet, ["TP", "FP", "TP"], "a", tmp_path)
    second = _labels(packet, ["TP", "TP", "TP"], "b", tmp_path)
    args = ["adjudicate", "--packet", str(tmp_path / "p.json"), "--key", str(tmp_path / "k.json"),
            "--labels", str(first), str(second), "--reviewer", "a", "b", "--out", str(tmp_path / "adj.json")]
    with pytest.raises(SystemExit, match="no judge verdict"):
        review.main(args)
    key = json.loads((tmp_path / "k.json").read_text())
    key["packet_sha256"] = "0" * 64
    (tmp_path / "k.json").write_text(json.dumps(key))
    with pytest.raises(SystemExit, match="different packet"):
        review.main(args)


def test_check_rejects_unsupported_high_confidence_and_retired_evidence(tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text(RULES)
    led = tmp_path / "led.json"
    led.write_text(json.dumps({"rules": {
        "javascript.parameter-shell-command": {"evidence_tier": "retire", "tp": 1, "decided": 25},
        "python.unsafe-deserialization-unscoped": {"evidence_tier": "review"}}}))
    assert review.main(["check", "--ledger", str(led), "--rules", str(rules)]) == 1
    led.write_text(json.dumps({"rules": {
        "python.unsafe-deserialization-unscoped": {"evidence_tier": "default"}}}))
    assert review.main(["check", "--ledger", str(led), "--rules", str(rules)]) == 0
