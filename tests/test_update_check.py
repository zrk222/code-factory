"""Update notifier — reports, never installs."""
from __future__ import annotations

import json

from factoryline.update_check import _parse_version, check_for_update, render


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
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    result = check_for_update(tmp_path, force=True)
    assert result["action"] is None
    assert "never installs" in result["note"] or "not an error" in result["note"]


def test_ahead_of_index_is_reported_plainly(tmp_path, monkeypatch):
    class FakeResponse:
        def read(self): return json.dumps({"info": {"version": "0.0.1"}}).encode()
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: FakeResponse())
    result = check_for_update(tmp_path, force=True)
    assert result["status"] == "ahead_of_index"
    assert "never published" in result["note"]


def test_render_tells_the_user_nothing_changed(tmp_path, monkeypatch):
    class FakeResponse:
        def read(self): return json.dumps({"info": {"version": "99.0.0"}}).encode()
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: FakeResponse())
    text = render(check_for_update(tmp_path, force=True))
    assert "pip install --upgrade" in text
    assert "Nothing was changed" in text
