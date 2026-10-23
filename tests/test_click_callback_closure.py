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


@pytest.mark.parametrize(
    "body",
    [
        "if False:\n        runner.invoke(cli, catch_exceptions=False)",
        "if True:\n        pass\n    else:\n        runner.invoke(cli, catch_exceptions=False)",
        "while False:\n        runner.invoke(cli, catch_exceptions=False)",
        "return\n    runner.invoke(cli, catch_exceptions=False)",
        "raise ValueError()\n    runner.invoke(cli, catch_exceptions=False)",
        "if flag:\n        return\n        runner.invoke(cli, catch_exceptions=False)",
    ],
    ids=[
        "if-false",
        "dead-else",
        "while-false",
        "after-return",
        "after-raise",
        "branch-local-return",
    ],
)
def test_unreachable_command_references_retain_local_weak_warning(tmp_path, body):
    source = (
        "import click\nfrom click.testing import CliRunner\n"
        "def test_behavior():\n"
        "    @click.command()\n    def cli():\n        assert compute() == 7\n"
        "    runner = CliRunner()\n    " + body + "\n"
    )
    (tmp_path / "test_cli.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    weak = [
        item
        for item in report["findings"]
        if item["code"] == "QUALITY_WEAK_TEST_ORACLE"
    ]
    assert len(weak) == 1
    assert weak[0]["severity"] == "MEDIUM"
    assert "only referenced in statically unreachable code" in weak[0]["message"]
    assert weak[0]["facts"]["whole_test_oracle"] == "UNASSESSED"
    assert "QUALITY_HOLLOW_TEST" not in report["finding_counts"]


@pytest.mark.parametrize(
    "body",
    [
        "if flag:\n        runner.invoke(cli, catch_exceptions=False)",
        "if True:\n        runner.invoke(cli, catch_exceptions=False)",
        "while flag:\n        runner.invoke(cli, catch_exceptions=False)",
        "try:\n        return\n    finally:\n        runner.invoke(cli, catch_exceptions=False)",
        "try:\n        raise ValueError()\n    except ValueError:\n        runner.invoke(cli, catch_exceptions=False)",
        "if False:\n        pass\n    else:\n        runner.invoke(cli, catch_exceptions=False)",
        "if False:\n        runner.invoke(cli, catch_exceptions=False)\n    capture(cli)",
        "if False:\n        runner.invoke(cli, catch_exceptions=False)\n    inspect(locals())",
        "def later():\n        runner.invoke(cli, catch_exceptions=False)\n    register(later)",
    ],
    ids=[
        "dynamic-if",
        "live-if",
        "dynamic-loop",
        "finally",
        "except",
        "live-else",
        "escape",
        "reflection",
        "closure",
    ],
)
def test_live_or_escaped_command_references_remain_conservative(tmp_path, body):
    (tmp_path / "test_cli.py").write_text(
        "import click\nfrom click.testing import CliRunner\n"
        "def test_behavior():\n"
        "    @click.command()\n    def cli():\n        assert compute() == 7\n"
        "    runner = CliRunner()\n    " + body + "\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_WEAK_TEST_ORACLE" not in report["finding_counts"]


def test_dead_reference_helper_binds_native_cache_epoch(tmp_path, monkeypatch):
    from factoryline import review_audits as scanner

    helper = test_callback_closure._reference_is_unreachable
    assert helper in test_callback_closure.CACHE_HELPERS
    before = scanner._oracle_context_cache_key(tmp_path, [], {})

    def replacement(*args):
        return False

    monkeypatch.setattr(helper, "__code__", replacement.__code__)
    assert scanner._oracle_context_cache_key(tmp_path, [], {}) != before
