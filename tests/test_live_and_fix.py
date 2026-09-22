import hashlib
import json
import sys

import pytest

from factoryline.fix_workflow import run_fix_workflow
from factoryline.live_feedback import LiveFeedbackError, run_live_feedback
from factoryline.senior_assurance import _source_digest


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _live(tmp_path, *, command=None):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
    return {
        "schema": "factory.live-feedback.v1",
        "live_id": "live-test",
        "contract_sha256": _digest("contract"),
        "changed_paths": ["src/app.py"],
        "checks": [
            {
                "id": "app-check",
                "paths": ["src/app.py"],
                "argv": command or [sys.executable, "check.py"],
                "expected_exit": 0,
                "timeout_seconds": 10,
                "max_output_bytes": 4096,
                "env": {"PYTHONIOENCODING": "utf-8"},
            },
            {
                "id": "unrelated-check",
                "paths": ["docs/guide.md"],
                "argv": [sys.executable, "check.py"],
                "expected_exit": 0,
                "timeout_seconds": 10,
                "max_output_bytes": 4096,
                "env": {},
            },
        ],
    }


def test_live_feedback_plans_only_affected_checks(tmp_path):
    (tmp_path / "check.py").write_text("print('ok')\n", encoding="utf-8")
    result = run_live_feedback(tmp_path, _live(tmp_path))
    assert result["mode"] == "plan"
    assert result["counts"] == {"PASS": 0, "FAIL": 0, "READY": 1, "SKIPPED": 1, "BLOCKED": 0}
    assert result["checks"][0]["next_action"].startswith("Run the same manifest")


def test_live_feedback_executes_affected_check_in_replay_workspace(tmp_path):
    (tmp_path / "check.py").write_text("print('ok')\n", encoding="utf-8")
    result = run_live_feedback(tmp_path, _live(tmp_path), execute=True)
    assert result["counts"]["PASS"] == 1
    assert result["counts"]["SKIPPED"] == 1
    assert result["checks"][0]["receipt_sha256"]
    assert result["authority"] == "none"


def test_live_feedback_rejects_network_or_publication_commands(tmp_path):
    (tmp_path / "check.py").write_text("print('ok')\n", encoding="utf-8")
    with pytest.raises(LiveFeedbackError) as error:
        run_live_feedback(tmp_path, _live(tmp_path, command=["curl", "https://example.test"]))
    assert error.value.code == "E_LIVE_SIDE_EFFECT"


def _replay(root, name, exit_code, contract):
    source = root / name
    source.mkdir()
    (source / "run.py").write_text(
        f"import sys; sys.exit({exit_code})\n", encoding="utf-8"
    )
    source_sha, _ = _source_digest(source)
    return {
        "schema": "factory.replay-manifest.v1",
        "replay_id": name,
        "source_root": name,
        "source_sha256": source_sha,
        "dependencies_sha256": contract,
        "policy_sha256": contract,
        "input_files": [],
        "argv": [sys.executable, "run.py"],
        "expected_exit": exit_code,
        "timeout_seconds": 10,
        "max_output_bytes": 4096,
        "contract_sha256": contract,
    }


def test_fix_workflow_provides_one_repair_handoff(tmp_path):
    contract = _digest("contract")
    manifest = {
        "schema": "factory.repair-comparison.v1",
        "comparison_id": "fix-1",
        "contract_sha256": contract,
        "buggy": _replay(tmp_path, "buggy", 1, contract),
        "fixed": _replay(tmp_path, "fixed", 0, contract),
        "negative_controls": [_replay(tmp_path, "control", 1, contract)],
    }
    result = run_fix_workflow(tmp_path, manifest)
    assert result["schema"] == "factory.fix-workflow.v1"
    assert result["state"] == "PLAN_ONLY"
    assert result["reproduction"]["required"] is True
    assert "--execute" in result["next_action"]
    assert result["release_approval"] is False
