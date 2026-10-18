from __future__ import annotations

import pytest

from factoryline import test_callback_closure
from factoryline.review_audits import security_scan


@pytest.mark.parametrize(
    ("setup", "mutation", "decorator"),
    [
        (
            "class RunOnCreate(click.Command):\n"
            "    def __init__(self, *args, callback, **kwargs):\n"
            "        callback()\n"
            "        super().__init__(*args, callback=callback, **kwargs)\n",
            "",
            "@click.command('cli', RunOnCreate)",
        ),
        (
            "def eager():\n    def wrap(fn):\n        fn()\n        return fn\n"
            "    return wrap\nclick.command = eager\n",
            "",
            "@click.command()",
        ),
        (
            "def eager():\n    def wrap(fn):\n        fn()\n        return fn\n"
            "    return wrap\n",
            "    monkeypatch.setattr(click, 'command', eager)\n",
            "@click.command()",
        ),
        (
            "def eager():\n    def wrap(fn):\n        fn()\n        return fn\n"
            "    return wrap\nclick.argument = eager\n",
            "",
            "@click.command()\n    @click.argument('arg')",
        ),
        (
            "from unittest.mock import patch as replace\n"
            "def eager():\n    def wrap(fn):\n        fn()\n        return fn\n"
            "    return wrap\nreplace('click.argument', eager).start()\n",
            "",
            "@click.command()\n    @click.argument('arg')",
        ),
        (
            "def eager():\n    def wrap(fn):\n        fn()\n        return fn\n"
            "    return wrap\nproviders = [click]\n"
            "providers[0].command = eager\n",
            "",
            "@click.command()",
        ),
        (
            "def eager():\n    def wrap(fn):\n        fn()\n        return fn\n"
            "    return wrap\nclick.__dict__['command'] = eager\n",
            "",
            "@click.command()",
        ),
        (
            "def eager():\n    def wrap(fn):\n        fn()\n        return fn\n"
            "    return wrap\nprovider = click.command\n"
            "provider.__code__ = eager.__code__\n",
            "",
            "@click.command()",
        ),
    ],
)
def test_uncertain_click_provider_or_callback_is_not_diagnosed(
    tmp_path, setup, mutation, decorator
):
    source = (
        "import click\n"
        + setup
        + "\ndef test_cli(monkeypatch):\n"
        + mutation
        + "    "
        + decorator
        + "\n    def cli(arg=None):\n        assert compute() == 7\n"
    )
    (tmp_path / "test_cli.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_WEAK_TEST_ORACLE" not in report["finding_counts"]


def test_ordinary_tests_skip_click_module_walk(tmp_path, monkeypatch):
    def unexpected_walk(*_args):
        pytest.fail("Click provider traversal ran without a local command candidate")

    monkeypatch.setattr(
        test_callback_closure, "_click_provider_escapes", unexpected_walk
    )
    (tmp_path / "test_smoke.py").write_text(
        "def test_smoke(): compute()\n", encoding="utf-8"
    )
    security_scan(tmp_path, cache_enabled=False)
