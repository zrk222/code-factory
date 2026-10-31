"""Execute the protected publication cadence snippets without external effects."""

import json
import subprocess
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from factoryline import release_candidate as candidate


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/publish.yml"


def _snippet(marker):
    text = WORKFLOW.read_text(encoding="utf-8")
    section = text.split(marker, 1)[1]
    return textwrap.dedent(
        section.split("python - <<'PY'\n", 1)[1].split("\n          PY", 1)[0]
    )


@pytest.mark.parametrize(
    "tag,actor,opt_in,accepted",
    [
        ("v0.49.5", "zrk222", "true", True),
        ("v0.49.5", "zrk222", "false", False),
        ("v0.49.5", "other-user", "true", False),
        ("v0.49.6", "zrk222", "true", False),
        ("v0.49.4", "zrk222", "true", False),
    ],
)
@pytest.mark.parametrize("recent_count", [1, 4])
def test_publish_0495_guard_keeps_cooldown_cap_and_exact_owner(
    tmp_path, monkeypatch, tag, actor, opt_in, accepted, recent_count
):
    monkeypatch.chdir(tmp_path)
    now = datetime.now(timezone.utc)
    Path("release-train.json").write_text(
        json.dumps(
            {
                "cadence": {
                    "effective_at": (now - timedelta(days=31)).isoformat(),
                    "max_releases_30d": 4,
                    "minimum_days_between_releases": 7,
                }
            }
        )
    )
    Path("release-history.json").write_text(
        json.dumps(
            [
                [
                    {
                        "draft": False,
                        "published_at": (now - timedelta(days=1)).isoformat(),
                    }
                ]
                * recent_count
            ]
        )
    )
    for key, value in {
        "RUNNER_TEMP": str(tmp_path),
        "RELEASE_TAG": tag,
        "GITHUB_ACTOR": actor,
        "CORE_0481_EXCEPTION": "false",
        "CORE_0482_EXCEPTION": "false",
        "CORE_0495_EXCEPTION": opt_in,
    }.items():
        monkeypatch.setenv(key, value)
    code = _snippet(
        "- name: Enforce cadence using actual GitHub publication timestamps"
    )
    if accepted:
        exec(compile(code, str(WORKFLOW), "exec"), {})
    else:
        with pytest.raises(SystemExit):
            exec(compile(code, str(WORKFLOW), "exec"), {})


def test_publish_0495_protected_exception_round_trips_exact_source_run(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    Path(".factory").mkdir()
    Path("contract.json").write_text(json.dumps({"approved_by": "zrk222"}))
    Path("release-train.json").write_text(
        json.dumps({"cadence": {"exceptions_enabled": False}})
    )
    for key, value in {
        "RELEASE_CONTRACT_PATH": "contract.json",
        "RELEASE_TAG": "v0.49.5",
        "GITHUB_ACTOR": "zrk222",
        "GITHUB_ACTIONS": "true",
        "GITHUB_RUN_ID": "12345",
        "GITHUB_RUN_ATTEMPT": "2",
        "CORE_0481_EXCEPTION": "false",
        "CORE_0482_EXCEPTION": "false",
        "CORE_0495_EXCEPTION": "true",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(subprocess, "check_output", lambda *args, **kwargs: "a" * 40)
    code = _snippet(
        "- name: Require sealed release candidate preflight before external publication"
    )
    exec(compile(code, str(WORKFLOW), "exec"), {})
    path = Path(".factory/core-0495-cadence-exception.json")
    result = candidate._cadence_exception_payload(
        tmp_path,
        path,
        {"version": "0.49.5", "commit": "a" * 40},
        "core",
        "v0.49.5",
        {"approved_by": "zrk222"},
    )
    assert result["monthly_cap_exception"] is True
    assert result["one_time_version_opt_in"] == "0.49.5"
    assert result["workflow_run_attempt"] == "2"
    assert result["source_commit"] == "a" * 40
    text = WORKFLOW.read_text(encoding="utf-8")
    assert (
        '"$RELEASE_TAG" == "v0.49.5" ]]; then source_args=(--source CHANGELOG.md)'
        in text
    )
    assert "signed_receipts fetch-ci" in text
    assert "environment: pypi" in text
    assert (
        "default: false"
        in text.split("core_0495_cadence_exception:", 1)[1].split("permissions:", 1)[0]
    )
