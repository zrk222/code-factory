"""Update notifier — reports, never installs."""

from __future__ import annotations

import json

from factoryline.cli import (
    _interactive_update_check_allowed,
    _notify_interactive_update,
)
from factoryline.update_check import (
    _parse_version,
    check_for_update,
    render,
    user_cache_path,
)


def test_version_comparison_orders_correctly():
    assert _parse_version("0.26.0") > _parse_version("0.24.2")
    assert _parse_version("0.10.0") > _parse_version("0.9.9")


def test_non_numeric_suffix_is_dropped_not_guessed():
    """A wrong ordering here would tell someone to downgrade."""
    assert _parse_version("1.2.3rc1") == (1, 2, 3)
    assert _parse_version("1.2.dev") == (1, 2)


def test_offline_returns_unavailable_and_does_not_raise(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise OSError("no network")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    result = check_for_update(tmp_path, force=True)
    assert result["status"] == "unavailable"
    assert "not an error" in result["note"]


def test_result_never_carries_an_install_side_effect(tmp_path, monkeypatch):
    """The action is a string for a human to run, never something executed."""
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda *a, **k: (_ for _ in ()).throw(OSError())
    )
    result = check_for_update(tmp_path, force=True)
    assert result["action"] is None
    assert "never installs" in result["note"] or "not an error" in result["note"]


def test_ahead_of_index_is_reported_plainly(tmp_path, monkeypatch):
    class FakeResponse:
        def read(self, _limit):
            return json.dumps({"info": {"version": "0.0.1"}}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: FakeResponse())
    result = check_for_update(tmp_path, force=True)
    assert result["status"] == "ahead_of_index"
    assert "never published" in result["note"]


def test_render_tells_the_user_nothing_changed(tmp_path, monkeypatch):
    class FakeResponse:
        def read(self, _limit):
            return json.dumps({"info": {"version": "99.0.0"}}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: FakeResponse())
    text = render(check_for_update(tmp_path, force=True))
    assert "pip install --upgrade" in text
    assert "Nothing was changed" in text


def test_update_check_uses_project_cache_for_explicit_command_and_reuses_it(
    tmp_path, monkeypatch
):
    calls = []

    class FakeResponse:
        def read(self, _limit):
            calls.append("network")
            return json.dumps({"info": {"version": "99.0.0"}}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: FakeResponse())
    first = check_for_update(tmp_path, force=True)
    second = check_for_update(tmp_path)
    assert first["status"] == second["status"] == "update_available"
    assert first["cached"] is False
    assert second["cached"] is True
    assert calls == ["network"]


def test_cache_is_rejected_when_timestamp_is_naive(tmp_path, monkeypatch):
    cache_path = tmp_path / ".factory" / "update-check.json"
    cache_path.parent.mkdir()
    cache_path.write_text(
        json.dumps(
            {
                "package": "factoryline-code-factory",
                "installed": "0.46.9",
                "latest": "99.0.0",
                "status": "update_available",
                "checked_at": "2026-09-26T12:00:00",
            }
        ),
        encoding="utf-8",
    )
    calls = []

    class FakeResponse:
        def read(self, _limit):
            calls.append("network")
            return json.dumps({"info": {"version": "0.46.9"}}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: FakeResponse())
    result = check_for_update(tmp_path)
    assert result["status"] == "current"
    assert result["cached"] is False
    assert calls == ["network"]


def test_unavailable_result_is_cached_for_a_day_without_repeated_timeout(
    tmp_path, monkeypatch
):
    calls = []

    def unavailable(*_args, **_kwargs):
        calls.append("network")
        raise OSError("offline")

    monkeypatch.setattr("urllib.request.urlopen", unavailable)
    first = check_for_update(tmp_path, force=True)
    second = check_for_update(tmp_path)
    assert first["status"] == second["status"] == "unavailable"
    assert first["cached"] is False
    assert second["cached"] is True
    assert calls == ["network"]


def test_overlong_cached_version_is_ignored_safely(tmp_path, monkeypatch):
    cache_path = tmp_path / ".factory" / "update-check.json"
    cache_path.parent.mkdir()
    cache_path.write_text(
        json.dumps(
            {
                "package": "factoryline-code-factory",
                "installed": "0.46.9",
                "latest": "9" * 5_000,
                "status": "update_available",
                "checked_at": "2026-09-26T12:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    calls = []

    class FakeResponse:
        def read(self, _limit):
            calls.append("network")
            return json.dumps({"info": {"version": "0.46.9"}}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: FakeResponse())
    result = check_for_update(tmp_path)
    assert result["status"] == "current"
    assert result["cached"] is False
    assert calls == ["network"]


def test_user_cache_is_outside_project_and_uses_platform_location(tmp_path):
    windows = user_cache_path(
        environ={"LOCALAPPDATA": str(tmp_path / "local")},
        system="Windows",
        home=tmp_path,
    )
    linux = user_cache_path(
        environ={"XDG_CACHE_HOME": str(tmp_path / "xdg")},
        system="Linux",
        home=tmp_path,
    )
    assert windows == tmp_path / "local" / "CodeFactory" / "cache" / "update-check.json"
    assert linux == tmp_path / "xdg" / "code-factory" / "update-check.json"


class _TTY:
    def isatty(self):
        return True


class _Pipe:
    def isatty(self):
        return False


def test_automatic_update_check_is_limited_to_successful_human_cli_runs():
    tty = _TTY()
    assert _interactive_update_check_allowed(
        ["audit"], stdin=tty, stderr=tty, environ={}
    )
    for argv, environment, input_stream, error_stream in (
        (["audit", "--json"], {}, tty, tty),
        (["version"], {}, tty, tty),
        (["studio"], {}, tty, tty),
        (["mcp", "serve"], {}, tty, tty),
        (["audit"], {"CI": "true"}, tty, tty),
        (["audit"], {"FACTORY_DISABLE_UPDATE_CHECK": "1"}, tty, tty),
        (["audit"], {}, _Pipe(), tty),
    ):
        assert not _interactive_update_check_allowed(
            argv, stdin=input_stream, stderr=error_stream, environ=environment
        )
    assert _interactive_update_check_allowed(
        ["audit"], stdin=tty, stderr=tty, environ={}
    )


def test_automatic_notice_prints_to_stderr_and_never_runs_on_failure(monkeypatch):
    from io import StringIO

    class TTYBuffer(StringIO):
        def isatty(self):
            return True

    output = TTYBuffer()
    latest = {
        "status": "update_available",
        "installed": "0.46.9",
        "latest": "99.0.0",
        "action": "pip install --upgrade factoryline-code-factory==99.0.0",
    }
    monkeypatch.setattr(
        "factoryline.update_check.check_for_update", lambda **kwargs: latest
    )
    monkeypatch.setattr(
        "factoryline.update_check.render", lambda result: "UPDATE NOTICE"
    )
    # This test covers output behavior; CI suppression is covered separately.
    # GitHub Actions sets CI/GITHUB_ACTIONS, which must not affect this seam.
    monkeypatch.setattr(
        "factoryline.cli._interactive_update_check_allowed", lambda *_args: True
    )
    monkeypatch.setattr("factoryline.cli.sys.stderr", output)
    monkeypatch.setattr("factoryline.cli.sys.stdin", TTYBuffer())
    _notify_interactive_update(["audit"], 0)
    assert output.getvalue() == "UPDATE NOTICE\n"
    output.seek(0)
    output.truncate(0)
    _notify_interactive_update(["audit"], 1)
    assert output.getvalue() == ""


def test_cli_main_runs_notice_after_successful_dispatch_only(monkeypatch):
    import factoryline.cli as cli

    checks = []
    monkeypatch.setattr(cli, "_dispatch", lambda _argv: 0)
    monkeypatch.setattr(
        cli,
        "_notify_interactive_update",
        lambda argv, code: checks.append((argv, code)),
    )
    monkeypatch.setattr(
        "factoryline.ops_telemetry.is_read_only_command", lambda _argv: True
    )
    assert cli.main(["doctor"]) == 0
    assert checks == [(["doctor"], 0)]

    monkeypatch.setattr(cli, "_dispatch", lambda _argv: 1)
    assert cli.main(["doctor"]) == 1
    assert checks == [(["doctor"], 0), (["doctor"], 1)]
