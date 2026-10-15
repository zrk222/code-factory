import builtins
import json
import subprocess
from pathlib import Path

from factoryline import provenance as bootstrap
from factoryline import provenance as provenance_module


def test_version_fast_path_does_not_import_command_registry(monkeypatch, capsys):
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "factoryline.cli":
            raise AssertionError("version probes must not import the full CLI registry")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    assert bootstrap.main(["--version", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "factoryline.provenance.v1"
    assert payload["package"] == "factoryline-code-factory"


def test_non_version_commands_delegate_to_full_cli(monkeypatch):
    calls = []

    class StubCli:
        @staticmethod
        def main(values):
            calls.append(values)
            return 7

    monkeypatch.setitem(__import__("sys").modules, "factoryline.cli", StubCli)
    assert bootstrap.main(["plan"]) == 7
    assert calls == [["plan"]]


def test_source_commit_fails_closed_when_git_status_times_out(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "factoryline-code-factory"\n',
        encoding="utf-8",
    )
    module_dir = tmp_path / "factoryline"
    module_dir.mkdir()

    calls = 0

    def run(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(args[0], 0, stdout="abc123\n", stderr="")
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(provenance_module.subprocess, "run", run)
    assert provenance_module._source_commit(module_dir) is None


def test_quick_help_is_small_actionable_and_does_not_load_registry(monkeypatch, capsys):
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "factoryline.cli":
            raise AssertionError("quick help must not load advanced commands")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    for flag in ("--help", "-h"):
        assert bootstrap.main([flag]) == 0
        text = capsys.readouterr().out
        assert len(text.splitlines()) <= 22
        for command in (
            "factory scan --root .",
            "factory studio --root .",
            "factory guide",
            "factory --help-all",
        ):
            assert command in text
        assert "INCOMPLETE" in text and "without running your project" in text
        for term in ("SSAT", "DAG", "Verifier Plane", "Survival Card", "Loop Passport"):
            assert term not in text


def test_advanced_help_and_explicit_commands_keep_original_dispatch(monkeypatch):
    calls = []

    class StubCli:
        @staticmethod
        def main(values):
            calls.append(values)
            return 7

    monkeypatch.setitem(__import__("sys").modules, "factoryline.cli", StubCli)
    pairs = [
        (["--help-all"], ["--help"]),
        ([], []),
        (["scan", "--help"], ["scan", "--help"]),
        (["--help", "--invalid"], ["--help", "--invalid"]),
        (["enterprise", "--help"], ["enterprise", "--help"]),
    ]
    for values, expected in pairs:
        assert bootstrap.main(values) == 7
        assert calls[-1] == expected


def test_home_operator_flow_shows_plan_only_action_without_dummy_commands(
    tmp_path, capsys
):
    from factoryline.cli import main as cli_main
    from factoryline.incremental_scheduler import SCHEMA

    manifest = {
        "schema": SCHEMA,
        "plan_id": "home-checks",
        "assurance_level": "isolated_worker",
        "changed_paths": ["src/a.py"],
        "dependency_closure": {"lint": ["src/a.py"]},
        "gates": [
            {"id": "lint", "depends_on": [], "side_effects": False, "proof": None}
        ],
    }
    (tmp_path / "schedule.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert (
        cli_main(
            ["home", "--root", str(tmp_path), "--schedule", "schedule.json", "--json"]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    action = payload["daily_action"]
    assert action["audit_state"] == "PLAN_ONLY"
    assert action["execution"] == "NOT_RUN"
    assert action["proof_counts"]["RUN"] == 1
    assert action["primary_action"]["id"] == "run_required_checks"
    assert payload["next"] == []
    assert not any("init" in value or "<feature>" in value for value in payload["next"])
    assert not (tmp_path / ".factory").exists()


def test_home_reports_status_reader_failure_as_incomplete(
    tmp_path, monkeypatch, capsys
):
    import factoryline.mission_control_status as status
    from factoryline.cli import main as cli_main

    def fail(_root, _schedule=None):
        raise OSError("local evidence unavailable")

    monkeypatch.setattr(status, "mission_control_status", fail)
    direct = status.read_daily_action(tmp_path)
    assert direct == status.incomplete_daily_action()
    assert direct["execution"] == "NOT_RUN"
    assert not any(direct["authority"].values())
    assert cli_main(["home", "--root", str(tmp_path), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["daily_action"]["audit_state"] == "INCOMPLETE"
    assert payload["daily_action"]["error_code"] == "STATUS_READ_FAILED"
    assert payload["daily_action"]["blockers"] == {}


def test_daily_action_rejects_boolean_counts_and_preserves_plan_only_states(tmp_path):
    import pytest
    from factoryline.mission_control_status import (
        daily_schedule_plan,
        project_daily_action,
    )

    manifest = {
        "schema": "factory.incremental-plan.v1",
        "plan_id": "daily-boundaries",
        "assurance_level": "isolated_worker",
        "changed_paths": ["a.py"],
        "dependency_closure": {},
        "gates": [
            {"id": "lint", "depends_on": [], "side_effects": False, "proof": None}
        ],
    }
    (tmp_path / "plan.json").write_text(json.dumps(manifest), encoding="utf-8")
    schedule = daily_schedule_plan(tmp_path, "plan.json")
    schedule["plan"]["counts"]["RUN"] = True
    with pytest.raises(ValueError, match="counts"):
        project_daily_action({"state": "evidence_missing", "blockers": {}}, schedule)
    for count in [True, -1, 1.5, None]:
        with pytest.raises(ValueError):
            project_daily_action({"state": "blocked", "blockers": {"bad": count}})


def test_daily_schedule_rejects_duplicate_keys_oversize_and_source_escape(tmp_path):
    from factoryline.mission_control_status import (
        DAILY_SCHEDULE_MAX_BYTES,
        daily_schedule_plan,
    )

    candidate = tmp_path / "plan.json"
    manifest = {
        "schema": "factory.incremental-plan.v1",
        "plan_id": "duplicate",
        "assurance_level": "isolated_worker",
        "changed_paths": ["a.py"],
        "dependency_closure": {},
        "gates": [
            {"id": "lint", "depends_on": [], "side_effects": False, "proof": None}
        ],
    }
    candidate.write_text(
        json.dumps(manifest).replace(
            '"plan_id": "duplicate"', '"plan_id": "first", "plan_id": "duplicate"'
        ),
        encoding="utf-8",
    )
    assert daily_schedule_plan(tmp_path, "plan.json")["state"] == "INCOMPLETE"
    candidate.write_bytes(b" " * (DAILY_SCHEDULE_MAX_BYTES + 1))
    assert daily_schedule_plan(tmp_path, "plan.json")["state"] == "INCOMPLETE"
    assert daily_schedule_plan(tmp_path, "../escape.json")["state"] == "INCOMPLETE"
    assert not (tmp_path / ".factory").exists()


def test_daily_schedule_rechecks_parent_identity_after_open(tmp_path, monkeypatch):
    import os
    from factoryline.mission_control_status import daily_schedule_plan

    nested = tmp_path / "nested"
    nested.mkdir()
    candidate = nested / "checks.json"
    candidate.write_text(
        json.dumps(
            {
                "schema": "factory.incremental-plan.v1",
                "plan_id": "race",
                "assurance_level": "isolated_worker",
                "changed_paths": ["a.py"],
                "dependency_closure": {},
                "gates": [
                    {
                        "id": "lint",
                        "depends_on": [],
                        "side_effects": False,
                        "proof": None,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    actual = os.open

    def concurrent_change(path, flags, *args, **kwargs):
        descriptor = actual(path, flags, *args, **kwargs)
        if Path(path) == candidate:
            (nested / "concurrent.txt").write_text("changed", encoding="utf-8")
        return descriptor

    monkeypatch.setattr(os, "open", concurrent_change)
    assert daily_schedule_plan(tmp_path, "nested/checks.json")["state"] == "INCOMPLETE"


def test_linear_connect_callback_rejects_bad_host_and_closes_listener(
    monkeypatch, capsys
):
    import http.client
    import threading
    from http.server import HTTPServer
    from factoryline import cli_integrations as cli

    requests, threads = [], []
    bound = {}

    class EphemeralServer(HTTPServer):
        def __init__(self, address, handler):
            assert address == ("127.0.0.1", 8767)
            super().__init__(("127.0.0.1", 0), handler)
            bound["server"] = self

    def browser_open(url):
        assert url == "https://linear.app/oauth/authorize?public-parameters"

        def callbacks():
            for host, code, status in [
                ("evil.test", "bad", 400),
                ("127.0.0.1:8767", "bad", 400),
                ("127.0.0.1:8767", "valid", 200),
            ]:
                connection = http.client.HTTPConnection(
                    *bound["server"].server_address, timeout=4
                )
                connection.request(
                    "GET", "/linear/callback?code=" + code, headers={"Host": host}
                )
                response = connection.getresponse()
                requests.append((response.status, response.read()))
                assert response.status == status
                connection.close()

        thread = threading.Thread(target=callbacks)
        threads.append(thread)
        thread.start()
        return True

    def complete(session, url, alias):
        assert alias == "work"
        if not url.endswith("code=valid"):
            raise ValueError("rejected")
        return {"state": "CONNECTED", "connection": alias}

    monkeypatch.setattr(cli, "HTTPServer", EphemeralServer)
    monkeypatch.setattr(cli.webbrowser, "open", browser_open)
    result = cli._linear_connect_callback(
        {"authorization_url": "https://linear.app/oauth/authorize?public-parameters"},
        "work",
        complete,
    )
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert result["state"] == "CONNECTED"
    assert [status for status, _ in requests] == [400, 400, 200]
    assert bound["server"].fileno() == -1
    assert "code=" not in capsys.readouterr().err


def test_issues_rejects_linear_connection_for_jira(monkeypatch, capsys):
    from factoryline import cli_integrations as cli

    def forbidden(*_args, **_kwargs):
        raise AssertionError("must not access the Linear vault or Jira provider")

    monkeypatch.setattr(cli, "_run_issue_evidence", forbidden)
    args = __import__("argparse").Namespace(
        action="import", provider="jira", connection="work", expert_token=False
    )
    assert cli._run_issues(args) == 2
    assert "incomplete" in capsys.readouterr().err


def test_linear_callback_stops_after_consumed_session_failure(monkeypatch):
    from factoryline import cli_integrations as cli

    session, outcome = {"state": "ephemeral"}, {}

    def failed(current, *_args):
        current.clear()
        raise ValueError("private provider response must not be disclosed")

    handler = cli._linear_callback_handler(session, "work", failed, outcome)
    callback = object.__new__(handler)
    callback.path = "/linear/callback?code=private&state=ephemeral"
    callback.headers = __import__("email.message", fromlist=["Message"]).Message()
    callback.headers["Host"] = "127.0.0.1:8767"
    errors = []
    monkeypatch.setattr(callback, "send_error", lambda *values: errors.append(values))
    callback.do_GET()
    assert outcome == {"error": "Linear token exchange or secure storage failed"}
    assert errors == [(400, "Connection not completed")]
    assert not session


def test_issues_routes_named_linear_and_explicit_jira_expert(monkeypatch):
    from factoryline import cli_integrations as cli, integrations
    from contextlib import contextmanager
    from argparse import Namespace

    selected = []

    @contextmanager
    def connection(alias):
        selected.append(alias)
        yield

    monkeypatch.setattr(integrations, "use_linear_connection", connection)
    monkeypatch.setattr(cli, "_run_issue_evidence", lambda args: 0)
    args = Namespace(
        action="import", provider="linear", connection="work", expert_token=False
    )
    assert cli._run_issues(args) == 0
    assert selected == ["work"]
    args.provider, args.connection, args.expert_token = "jira", None, True
    assert cli._run_issues(args) == 0
    assert selected == ["work"]
