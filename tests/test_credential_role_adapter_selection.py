"""Unrelated configuration defaults must not hide a declared HTTP adapter."""

import ast
from types import SimpleNamespace

from factoryline import credential_role_adapter_selection as selection


def _source(default):
    return ast.parse(
        "class Settings:\n"
        "    @property\n"
        "    def ADAPTER(self):\n"
        f"        return self._setting('ADAPTER', '{default}')\n"
    )


def _snapshots(tmp_path, second_http=False):
    snapshots = {
        tmp_path / "account_settings.py": _source("account.AccountAdapter"),
        tmp_path / "social_settings.py": _source("social.SocialAdapter"),
        tmp_path / "account.py": ast.parse(
            "class AccountAdapter:\n    def login(self):\n        pass\n"
        ),
        tmp_path / "social.py": ast.parse(
            "class SocialAdapter:\n    def get_requests_session(self):\n        pass\n"
        ),
    }
    if second_http:
        snapshots[tmp_path / "account.py"] = ast.parse(
            "class AccountAdapter:\n    def get_requests_session(self):\n        pass\n"
        )
    index = SimpleNamespace(
        root=tmp_path,
        snapshots=snapshots,
        relative=lambda path: path.relative_to(tmp_path).as_posix(),
    )
    return index, snapshots


def test_unrelated_adapter_defaults_do_not_block_http_candidate(tmp_path, monkeypatch):
    index, snapshots = _snapshots(tmp_path)
    monkeypatch.setattr(
        selection, "_setting_getter_shape", lambda _: (tmp_path / "utils.py", object())
    )
    selected = selection._declared_default(index, snapshots)
    assert selected is not None
    assert selected[0] == tmp_path / "social_settings.py"
    assert selected[7] == tmp_path / "social.py"


def test_two_http_adapter_defaults_remain_ambiguous(tmp_path, monkeypatch):
    index, snapshots = _snapshots(tmp_path, second_http=True)
    monkeypatch.setattr(
        selection, "_setting_getter_shape", lambda _: (tmp_path / "utils.py", object())
    )
    assert selection._declared_default(index, snapshots) is None
