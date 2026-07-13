from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_policy_examples_follow_the_default_cli_contract():
    for language in ("python", "typescript"):
        example = ROOT / "examples" / "verify-policy" / language
        policy = json.loads((example / "factory.policy.json").read_text(encoding="utf-8"))
        challenge = json.loads((example / "policy.challenge.json").read_text(encoding="utf-8"))
        assert policy["release"]["require_ci"] is True
        assert policy["quality"]["require_hollow_tests"] is True
        assert isinstance(challenge["command"], list)
        assert "{policy}" in challenge["command"]


def test_adoption_assets_are_present_and_measurement_is_raw_source_only():
    gif = ROOT / "docs" / "assets" / "verify-policy.gif"
    assert gif.read_bytes().startswith(b"GIF")
    launch = (ROOT / "scripts" / "capture_launch_metrics.ps1").read_text(encoding="utf-8")
    assert "pypistats.org/api/packages" in launch
    assert "traffic/views" in launch and "traffic/clones" in launch
    assert "not unique users or attributed conversions" in launch
