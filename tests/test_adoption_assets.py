from __future__ import annotations

import json
from pathlib import Path
import runpy


ROOT = Path(__file__).resolve().parents[1]


def test_policy_examples_follow_the_default_cli_contract():
    for language in ("python", "typescript"):
        example = ROOT / "examples" / "verify-policy" / language
        policy = json.loads(
            (example / "factory.policy.json").read_text(encoding="utf-8")
        )
        challenge = json.loads(
            (example / "policy.challenge.json").read_text(encoding="utf-8")
        )
        assert policy["release"]["require_ci"] is True
        assert policy["quality"]["require_hollow_tests"] is True
        assert isinstance(challenge["command"], list)
        assert "{policy}" in challenge["command"]


def test_adoption_assets_are_present_and_measurement_is_raw_source_only():
    gif = ROOT / "docs" / "assets" / "verify-policy.gif"
    assert gif.read_bytes().startswith(b"GIF")
    launch = (ROOT / "scripts" / "capture_launch_metrics.ps1").read_text(
        encoding="utf-8"
    )
    assert "pypistats.org/api/packages" in launch
    assert "traffic/views" in launch and "traffic/clones" in launch
    assert "not unique users or attributed conversions" in launch


def test_policy_gif_renderer_font_fallback_and_frame_layout(monkeypatch):
    module = runpy.run_path(str(ROOT / "scripts" / "render_verify_policy_gif.py"))

    monkeypatch.setattr(module["Path"], "exists", lambda _self: False)
    fallback = module["font"](18)
    assert fallback is not None
    frame = module["frame"]([("verified", "contract accepted")])
    assert frame.size == (module["WIDTH"], module["HEIGHT"])
    assert frame.mode == "RGB"
    assert frame.getpixel((0, 0)) == (32, 34, 45)
    assert frame.getpixel((50, 50)) == (52, 55, 70)
