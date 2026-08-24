from __future__ import annotations

import json
from pathlib import Path

from factoryline.combine import score_combine, seal_combine_task, verify_combine_scoreboard
from test_agent_license import AGENT, _passport, _record


SECOND_AGENT = {"schema": "factory.agent-identity.v1", "subject": "agent-bravo", "provider": "deepseek", "model": "flash"}


def _task(root: Path) -> Path:
    source = root / ".factory" / "compare-task.json"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(json.dumps({
        "schema": "factory.combine-task.v1", "id": "approval-tracker", "description": "Build the sealed approval tracker task.",
        "agents": [AGENT, SECOND_AGENT],
    }), encoding="utf-8")
    return source


def test_combine_scores_exact_governed_events_and_rejects_tampering(tmp_path: Path):
    passport = _passport(tmp_path)
    task = seal_combine_task(tmp_path, _task(tmp_path))
    _record(tmp_path, passport, AGENT, "alpha-run", task_id="approval-tracker")
    _record(tmp_path, passport, SECOND_AGENT, "bravo-run", passed=False, failures=["wrong_output"], task_id="approval-tracker")

    scored = score_combine(tmp_path, Path(task["path"]))
    verified = verify_combine_scoreboard(Path(scored["path"]))

    assert scored["scoreboard"]["summary"]["passed_count"] == 1
    assert scored["scoreboard"]["summary"]["unobserved"]["tokens"] is None
    assert [row["rank"] for row in scored["scoreboard"]["candidates"]] == [1, 2]
    assert verified["ok"] is True

    payload = json.loads(Path(scored["path"]).read_text(encoding="utf-8"))
    payload["candidates"][0]["rank"] = 2
    Path(scored["path"]).write_text(json.dumps(payload), encoding="utf-8")
    assert verify_combine_scoreboard(Path(scored["path"]))["ok"] is False
