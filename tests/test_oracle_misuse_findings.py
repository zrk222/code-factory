from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from factoryline.review_audits import security_scan


@pytest.mark.parametrize(
    ("assertion", "reason"),
    [
        (
            "assert (compute(), expected)",
            "nonempty container assertion is always truthy",
        ),
        (
            "assert {'actual': compute()}",
            "nonempty mapping assertion is always truthy",
        ),
    ],
)
def test_security_scan_reports_statically_truthy_assertions(
    tmp_path, assertion, reason
):
    (tmp_path / "test_vacuous.py").write_text(
        f"def compute(): return 1\ndef test_behavior():\n    {assertion}\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    findings = [
        item
        for item in report["findings"]
        if item["code"] == "QUALITY_WEAK_TEST_ORACLE"
    ]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "MEDIUM"
    assert reason in finding["message"]
    assert finding["facts"]["whole_test_oracle"] == "UNASSESSED"
    assert finding["facts"]["execution_state"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("assertion", ["assert True", "assert 2 == 1 + 1"])
def test_literal_only_assertion_has_provably_inert_test_body(tmp_path, assertion):
    # Unlike the container cases above, every expression completes independently
    # of production behavior. The complete-body proof therefore warrants HOLLOW.
    (tmp_path / "test_vacuous.py").write_text(
        f"def compute(): return 1\ndef test_behavior():\n    {assertion}\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}
    assert report["findings"][0]["severity"] == "MEDIUM"


def test_specific_local_defect_survives_an_independent_strong_assertion(tmp_path):
    (tmp_path / "test_mixed.py").write_text(
        "def compute(): return 1\n"
        "def test_mixed():\n"
        "    assert compute() == 1\n"
        "    assert (compute(), 1)\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    findings = [
        item
        for item in report["findings"]
        if item["code"] == "QUALITY_WEAK_TEST_ORACLE"
    ]
    assert len(findings) == 1
    assert "nonempty container assertion" in findings[0]["message"]


@pytest.mark.parametrize(
    "body,expected",
    [
        ("return 'plain'", "QUALITY_HOLLOW_TEST"),
        ("return load_style()", "QUALITY_WEAK_TEST_ORACLE"),
    ],
)
def test_discarded_comparison_requires_whole_body_completion(tmp_path, body, expected):
    (tmp_path / "test_style.py").write_text(
        f"def get_style(): {body}\ndef test_style():\n    get_style() == 'minimal'\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    findings = [item for item in report["findings"] if item["code"] == expected]
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    if expected == "QUALITY_WEAK_TEST_ORACLE":
        assert "comparison result is discarded" in findings[0]["message"]
        assert findings[0]["facts"]["whole_test_oracle"] == "UNASSESSED"
    else:
        assert report["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_comparison_result_consumed_with_side_effect_is_not_discarded(tmp_path):
    (tmp_path / "test_effect.py").write_text(
        "seen = []\n"
        "def inspect():\n    seen.append('called')\n    return 1\n"
        "def test_effect():\n"
        "    seen.append(inspect() == 1)\n"
        "    assert seen == ['called', True]\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_WEAK_TEST_ORACLE" not in report["finding_counts"]


def test_real_stacked_click_callback_remains_actionable(tmp_path):
    cases = json.loads(
        (Path(__file__).parent / "fixtures/external_oracle_cases.json").read_text()
    )
    source = next(
        item["source"]
        for item in cases
        if item["id"] == "click-test_open_file_pathlib_dash"
    )
    (tmp_path / "test_cli.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    findings = [
        item
        for item in report["findings"]
        if item["code"] == "QUALITY_WEAK_TEST_ORACLE"
    ]
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert "never invoked or referenced" in findings[0]["message"]
    assert findings[0]["facts"]["whole_test_oracle"] == "UNASSESSED"


def test_global_callback_binding_is_not_proven_uninvoked(tmp_path):
    (tmp_path / "test_cli.py").write_text(
        "import click\ncli = None\n"
        "def test_cli():\n    global cli\n"
        "    @click.command()\n    def cli():\n        assert compute() == 7\n"
        "    globals().get('cli')\n"
        "def teardown_function():\n    cli.main([], standalone_mode=False)\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_WEAK_TEST_ORACLE" not in report["finding_counts"]


@pytest.mark.parametrize(
    "body,expected,severity",
    [
        ("return 4", "QUALITY_HOLLOW_TEST", "MEDIUM"),
        ("return product()", "QUALITY_UNKNOWN_TEST_ORACLE", "INFO"),
    ],
)
def test_compute_smoke_requires_closed_completion(tmp_path, body, expected, severity):
    (tmp_path / "test_smoke.py").write_text(
        f"def compute(): {body}\ndef test_smoke(): compute()\n", encoding="utf-8"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"] == {expected: 1}
    assert report["findings"][0]["severity"] == severity
    assert "QUALITY_WEAK_TEST_ORACLE" not in report["finding_counts"]


def test_meaningful_click_callback_is_not_downgraded(tmp_path):
    (tmp_path / "test_cli.py").write_text(
        textwrap.dedent(
            """\
            import click
            from click.testing import CliRunner

            def test_cli_callback():
                @click.command()
                def cli():
                    value = int("7")
                    assert value == 7

                runner = CliRunner()
                runner.invoke(cli, [], catch_exceptions=False)
            """
        ),
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_WEAK_TEST_ORACLE" not in report["finding_counts"]
    assert "QUALITY_UNKNOWN_TEST_ORACLE" not in report["finding_counts"]


def test_shadowed_type_providers_are_not_treated_as_universal_builtin(tmp_path):
    (tmp_path / "test_provider.py").write_text(
        "def isinstance(value, expected): return value == expected\n"
        "def object(): return 'ok'\n"
        "def test_provider(): assert isinstance(object(), str)\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_WEAK_TEST_ORACLE" not in report["finding_counts"]


@pytest.mark.parametrize(
    "source",
    [
        "def noop(value): pass\ndef test_case(): noop('stable')\n",
        "def noop(value): return None\ndef test_case(): noop(7)\n",
        "def constant(value): return 4\ndef test_case(): constant('stable')\n",
        "def test_case():\n    def noop(value): pass\n    noop('stable')\n",
        "def test_case():\n    def noop(value): return None\n    noop(7)\n",
        "def test_case():\n    def constant(value): return 4\n    constant('stable')\n",
    ],
)
def test_source_bound_inert_helpers_accept_literal_arguments(tmp_path, source):
    (tmp_path / "test_helpers.py").write_text(source, encoding="utf-8")

    report = security_scan(tmp_path, cache_enabled=False)

    assert report["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            textwrap.dedent(
                """\
                async def compute():
                    return 3
                def run_async_fn(callback):
                    callback()
                def test_behavior():
                    async def check():
                        assert await compute() == 3
                    run_async_fn(check)
                """
            ),
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            textwrap.dedent(
                """\
                def run_async_fn(callback):
                    callback()
                def test_behavior():
                    def check():
                        unknown_effect()
                    run_async_fn(check)
                """
            ),
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            textwrap.dedent(
                """\
                def decorate(function):
                    return function
                def test_behavior():
                    @decorate
                    async def check():
                        assert compute() == 3
                    check()
                """
            ),
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            textwrap.dedent(
                """\
                def noop(callback):
                    pass
                def decorate(function):
                    return function
                def test_behavior():
                    @decorate
                    async def check():
                        assert compute() == 3
                    noop(check)
                """
            ),
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            textwrap.dedent(
                """\
                async def compute():
                    return 3
                try:
                    raise ValueError()
                except ValueError as compute:
                    pass
                def test_behavior():
                    compute()
                """
            ),
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            textwrap.dedent(
                """\
                async def compute():
                    return 3
                match 1:
                    case compute:
                        pass
                def test_behavior():
                    compute()
                """
            ),
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            textwrap.dedent(
                """\
                async def compute():
                    return 3
                if True:
                    def compute():
                        raise RuntimeError()
                def test_behavior():
                    compute()
                """
            ),
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            textwrap.dedent(
                """\
                async def compute():
                    return 3
                if False:
                    from source import replacement as compute
                def test_behavior():
                    compute()
                """
            ),
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            textwrap.dedent(
                """\
                def dispatch(callback):
                    callback()
                try:
                    raise ValueError()
                except ValueError as dispatch:
                    pass
                def test_behavior():
                    async def check():
                        assert compute() == 3
                    dispatch(check)
                """
            ),
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            textwrap.dedent(
                """\
                async def compute():
                    return 3
                def decorate(function):
                    return function
                @decorate
                async def decorated():
                    return 3
                def test_behavior():
                    decorated()
                """
            ),
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            textwrap.dedent(
                """\
                async def compute():
                    return 3
                compute = external_compute
                def test_behavior():
                    compute()
                """
            ),
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            textwrap.dedent(
                """\
                retained = []
                async def compute():
                    return 3
                retained.append(compute)
                def test_behavior():
                    compute()
                """
            ),
            {
                "QUALITY_UNKNOWN_TEST_ORACLE": 1,
                "QUALITY_UNAWAITED_COROUTINE": 1,
            },
        ),
        (
            textwrap.dedent(
                """\
                async def compute():
                    return 3
                alias = compute
                def test_behavior():
                    alias()
                """
            ),
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            textwrap.dedent(
                """\
                def run_async_fn(callback):
                    unknown_effect(callback)
                def noop(callback):
                    pass
                def test_behavior():
                    async def check():
                        assert compute() == 3
                    run_async_fn = noop
                    run_async_fn(check)
                """
            ),
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            textwrap.dedent(
                """\
                async def compute():
                    return 3
                def test_behavior():
                    compute()
                """
            ),
            {
                "QUALITY_HOLLOW_TEST": 1,
                "QUALITY_UNAWAITED_COROUTINE": 1,
            },
        ),
    ],
    ids=[
        "sync-callback-without-await",
        "executed-sync-callback",
        "decorated-local-coroutine",
        "decorated-callback-to-noop",
        "exception-target-coroutine",
        "match-capture-coroutine",
        "conditional-coroutine-definition",
        "conditional-import-binding",
        "exception-target-callback-helper",
        "decorated-coroutine",
        "rebound-coroutine",
        "escaped-coroutine",
        "aliased-coroutine",
        "local-noop-rebind",
        "ignored-module-coroutine",
    ],
)
def test_closed_async_helper_paths_and_negative_controls(tmp_path, source, expected):
    (tmp_path / "test_async.py").write_text(source, encoding="utf-8")

    report = security_scan(tmp_path, cache_enabled=False)

    assert report["finding_counts"] == expected


@pytest.mark.parametrize(
    "source",
    [
        "def test_case(): noop('stable')\n",
        "def noop(value): pass\ndef test_case(value): noop(value)\n",
        "def noop(value): pass\ndef test_case(): noop()\n",
        "def noop(value, value): pass\ndef test_case(): noop(1, 2)\n",
        "def noop(value): do_work(value)\ndef test_case(): noop('stable')\n",
        "def noop(value): raise RuntimeError()\ndef test_case(): noop('stable')\n",
        "def decorate(function): return function\n@decorate\ndef noop(value): pass\n"
        "def test_case(): noop('stable')\n",
        "def noop(value): pass\nnoop = other\ndef test_case(): noop('stable')\n",
        textwrap.dedent(
            """\
            def test_case():
                async def callback():
                    assert compute() == 3
                dispatch(callback)
            """
        ),
        textwrap.dedent(
            """\
            def decorate(function):
                return function
            @decorate
            def dispatch(callback):
                callback()
            def test_case():
                async def callback():
                    assert compute() == 3
                dispatch(callback)
            """
        ),
        textwrap.dedent(
            """\
            def dispatch(callback):
                callback()
            dispatch = external_dispatch
            def test_case():
                async def callback():
                    assert compute() == 3
                dispatch(callback)
            """
        ),
        textwrap.dedent(
            """\
            retained = []
            def dispatch(callback):
                callback()
            retained.append(dispatch)
            def test_case():
                async def callback():
                    assert compute() == 3
                dispatch(callback)
            """
        ),
        textwrap.dedent(
            """\
            def dispatch(callback):
                register(callback)
            def test_case():
                async def callback():
                    assert compute() == 3
                dispatch(callback)
            """
        ),
    ],
)
def test_unresolved_or_effectful_helpers_remain_unknown(tmp_path, source):
    (tmp_path / "test_helpers.py").write_text(source, encoding="utf-8")

    report = security_scan(tmp_path, cache_enabled=False)

    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


def test_parameter_self_identity_is_proven_inert(tmp_path):
    (tmp_path / "test_identity.py").write_text(
        "def test_case(obj):\n    assert obj is obj\n", encoding="utf-8"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "source",
    [
        "def test_case(obj):\n    assert obj == obj\n",
        "def test_case(obj):\n    assert obj <= obj\n",
        "def test_case(obj):\n    assert obj >= obj\n",
        "def test_case(obj):\n    obj = 1\n    assert obj is obj\n",
        "def test_case(obj):\n    del obj\n    assert obj is obj\n",
        "def test_case(obj):\n    def capture(): return obj\n    assert obj is obj\n",
        'def test_case(obj):\n    locals()["obj"] = None\n    assert obj is obj\n',
    ],
)
def test_nonidentity_or_unstable_name_comparisons_remain_unknown(tmp_path, source):
    (tmp_path / "test_identity.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


def test_inverse_self_identity_is_not_hollow(tmp_path):
    (tmp_path / "test_identity.py").write_text(
        "def test_case(obj):\n    assert obj is not obj\n", encoding="utf-8"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_HOLLOW_TEST" not in report["finding_counts"]


@pytest.mark.parametrize(
    "binding,error",
    [
        (
            "try:\n    raise ValueError()\nexcept ValueError as compute:\n    pass\n",
            NameError,
        ),
        ("match 1:\n    case compute:\n        pass\n", TypeError),
        ("if True:\n    def compute():\n        raise RuntimeError()\n", RuntimeError),
    ],
    ids=[
        "exception-deletes-binding",
        "match-overwrites-binding",
        "conditional-redefinition",
    ],
)
def test_coroutine_binding_counterexamples_really_raise(tmp_path, binding, error):
    source = (
        "async def compute():\n    return 3\n"
        + binding
        + "def test_case(): compute()\n"
    )
    namespace = {}
    exec(compile(source, "<binding-counterexample>", "exec"), namespace)
    with pytest.raises(error):
        namespace["test_case"]()
    (tmp_path / "test_binding.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


@pytest.mark.parametrize(
    "name",
    [
        "_module_helper_kind",
        "_module_binding_conflict",
        "_callback_helper_parameter",
        "_module_helper_references_closed",
        "_inert_coroutine_signature",
        "_coroutine_call_arity_matches",
        "_module_mock_constructors",
        "_mock_constructor_kind",
        "_mock_state_assertion_call",
        "_inert_assigned_coroutine_creation",
    ],
)
def test_completion_catalog_helpers_bind_native_cache_epoch(
    tmp_path, monkeypatch, name
):
    from factoryline import review_audits as scanner
    from factoryline import test_oracle_misuse as misuse

    helper = getattr(misuse, name)
    assert helper in misuse.INERT_BODY_HELPERS
    before = scanner._oracle_context_cache_key(tmp_path, [], {})

    def replacement(*args, **kwargs):
        return None

    monkeypatch.setattr(helper, "__code__", replacement.__code__)
    assert scanner._oracle_context_cache_key(tmp_path, [], {}) != before


@pytest.mark.parametrize(
    "source",
    [
        "from unittest.mock import AsyncMock\n"
        "async def test_behavior():\n"
        "    send = AsyncMock()\n    send.assert_not_awaited()\n",
        "from unittest.mock import AsyncMock\n"
        "from starlette.requests import Request\n"
        "async def test_behavior():\n"
        "    send = AsyncMock()\n"
        "    def unused():\n"
        "        request = Request({'type': 'http'}, send=send)\n"
        "        request.send_early_hints([])\n"
        "    send.assert_not_awaited()\n",
        "from unittest.mock import Mock\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    dependency.assert_not_called()\n",
        "from unittest.mock import Mock\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    if False:\n        ret = (lambda f: None)(dependency)\n"
        "    dependency.assert_not_called()\n",
        "from unittest.mock import Mock\n"
        "async def perform(dep):\n    pass\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    ret = perform(dependency)\n"
        "    dependency.assert_not_called()\n",
    ],
    ids=[
        "untouched-async-mock",
        "uninvoked-helper-with-request-calls",
        "untouched-mock",
        "constant-false-branch",
        "assigned-unawaited-source-coroutine",
    ],
)
def test_source_closed_untouched_mock_state_is_nonraising_but_not_an_oracle(
    tmp_path, source
):
    (tmp_path / "test_mock_completion.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"].get("QUALITY_HOLLOW_TEST") == 1
    assert "QUALITY_UNKNOWN_TEST_ORACLE" not in report["finding_counts"]


@pytest.mark.parametrize(
    "source",
    [
        "from unittest.mock import AsyncMock\n"
        "async def test_behavior():\n    dependency = AsyncMock()\n"
        "    dependency.assert_called_once()\n",
        "from unittest.mock import Mock\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    dependency()\n    dependency.assert_not_called()\n",
        "from unittest.mock import Mock\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    escaped = dependency\n    dependency.assert_not_called()\n",
        "from unittest.mock import Mock\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    dependency.assert_not_called = lambda: None\n"
        "    dependency.assert_not_called()\n",
        "from unittest.mock import Mock\n"
        "def Mock():\n    return object()\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    dependency.assert_not_called()\n",
        "from unittest.mock import Mock\n"
        "constructor = Mock\n"
        "def test_behavior():\n    dependency = constructor()\n"
        "    dependency.assert_not_called()\n",
        "import unittest.mock as um\n"
        "class Fake:\n"
        "    def assert_not_called(self):\n"
        "        raise AssertionError()\n"
        "um.Mock = Fake\n"
        "from unittest.mock import Mock\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    dependency.assert_not_called()\n",
        "from unittest.mock import Mock as Alias, Mock\n"
        "Alias.assert_not_called = lambda self: (_ for _ in ()).throw(AssertionError())\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    dependency.assert_not_called()\n",
        "from unittest.mock import patch, Mock\n"
        "class Fake:\n"
        "    def assert_not_called(self):\n"
        "        raise AssertionError()\n"
        "patch('unittest.mock.Mock', Fake).start()\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    dependency.assert_not_called()\n",
        "from unittest.mock import Mock\n"
        "def test_behavior():\n    dependency = Mock(name='dependency')\n"
        "    dependency.assert_not_called()\n",
        "from unittest.mock import Mock\n"
        "@identity\nasync def perform(dep):\n    pass\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    ret = perform(dependency)\n"
        "    dependency.assert_not_called()\n",
        "from unittest.mock import Mock\n"
        "async def perform(dep):\n    pass\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    perform = unknown\n    ret = perform(dependency)\n"
        "    dependency.assert_not_called()\n",
        "from starlette.requests import Request\n"
        "from unittest.mock import AsyncMock\n"
        "async def test_behavior():\n    send = AsyncMock()\n"
        "    request = Request({'type': 'http'}, send=send)\n"
        "    send.assert_not_awaited()\n",
        "from sys import modules as loaded\n"
        "loaded['unittest.mock'].Mock.assert_not_called = "
        "lambda self: (_ for _ in ()).throw(AssertionError())\n"
        "from unittest.mock import Mock\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    dependency.assert_not_called()\n",
        "from sys import modules as loaded\n"
        "async def compute():\n    return 3\n"
        "def fail():\n    raise RuntimeError()\n"
        "loaded[__name__].compute = fail\n"
        "def test_behavior():\n    compute()\n",
        "from unittest.mock import Mock\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    def dependency():\n        pass\n"
        "    dependency.assert_not_called()\n",
        "from unittest.mock import AsyncMock\n"
        "async def test_behavior():\n    dependency = AsyncMock()\n"
        "    async def dependency():\n        pass\n"
        "    dependency.assert_not_awaited()\n",
        "from unittest.mock import Mock\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    try:\n        def dependency():\n            pass\n"
        "    finally:\n        dependency.assert_not_called()\n",
        "from unittest.mock import Mock\n"
        "def test_behavior():\n    dependency = Mock()\n"
        "    try:\n        def dependency():\n            pass\n"
        "    except RuntimeError:\n        pass\n"
        "    else:\n        dependency.assert_not_called()\n",
    ],
    ids=[
        "raising-assert-called-once",
        "real-mock-call",
        "escaped-mock-instance",
        "mutated-assertion-method",
        "shadowed-constructor-provider",
        "escaped-constructor-provider",
        "mutated-module-mock-provider",
        "mutated-imported-mock-alias-method",
        "patched-mock-provider",
        "configured-constructor-arguments",
        "decorated-coroutine-helper",
        "rebound-coroutine-helper",
        "executed-request-constructor",
        "sys-modules-mutated-mock-provider",
        "sys-modules-mutated-source-helper",
        "mock-instance-shadowed-by-function",
        "async-mock-instance-shadowed-by-function",
        "try-finally-instance-shadowed-by-function",
        "try-else-instance-shadowed-by-function",
    ],
)
def test_mock_completion_keeps_raising_or_opaque_paths_unknown(tmp_path, source):
    (tmp_path / "test_mock_completion.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_HOLLOW_TEST" not in report["finding_counts"]
    assert report["finding_counts"].get("QUALITY_UNKNOWN_TEST_ORACLE") == 1


@pytest.mark.parametrize(
    "package", ["unittest.py", "unittest/__init__.py", "src/unittest/mock.py"]
)
def test_local_unittest_provider_cannot_prove_inert_mock(tmp_path, package):
    path = tmp_path / package
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "class Mock:\n    def assert_not_called(self):\n        raise AssertionError('local provider')\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from unittest.mock import Mock\n"
        "def test_case():\n    dependency = Mock()\n    dependency.assert_not_called()\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


def test_missing_captured_provider_context_cannot_prove_inert_mock():
    import ast
    from factoryline.test_oracle_misuse import inert_test_completion

    module = ast.parse(
        "from unittest.mock import Mock\ndef test_case():\n    m = Mock()\n    m.assert_not_called()\n"
    )
    test = module.body[-1]
    test._oracle_module = module
    assert inert_test_completion(test)[0] == "UNKNOWN"


@pytest.mark.parametrize(
    "name",
    [
        "_module_mock_imports",
        "_module_mock_constructors",
        "_mock_constructor_kind",
        "_mock_state_assertion_call",
        "_inert_coroutine_signature",
        "_coroutine_call_arity_matches",
        "_inert_assigned_coroutine_creation",
    ],
)
def test_mock_completion_helpers_bind_native_cache_epoch(tmp_path, monkeypatch, name):
    from factoryline import review_audits as scanner
    from factoryline import test_oracle_misuse as misuse

    helper = getattr(misuse, name)
    assert helper in misuse.INERT_BODY_HELPERS
    before = scanner._oracle_context_cache_key(tmp_path, [], {})

    def replacement(*args, **kwargs):
        return None

    monkeypatch.setattr(helper, "__code__", replacement.__code__)
    assert scanner._oracle_context_cache_key(tmp_path, [], {}) != before


@pytest.mark.parametrize(
    "sibling",
    [
        "from unittest.mock import Mock as Other\nOther.assert_not_called = lambda self: (_ for _ in ()).throw(AssertionError('sibling mutation'))\n",
        "import unittest.mock as other\nother.Mock.assert_not_called = lambda self: None\n",
        "from unittest.mock import *\n",
        "from unittest import mock\n",
        "from sys import modules as loaded\nloaded['unittest.mock'].Mock.assert_not_called = lambda self: None\n",
        "from importlib import import_module as load\nload('unittest.mock').Mock.assert_not_called = lambda self: None\n",
        "from builtins import getattr as attr\nattr(__import__('unittest.mock'), 'Mock')\n",
        "from unittest.mock import Mock\ndef test_sibling():\n    m = Mock()\n    m.assert_not_called()\n",
    ],
    ids=[
        "class-method-write",
        "module-alias",
        "wildcard",
        "package-import",
        "registry-alias",
        "dynamic-import",
        "reflected-provider",
        "benign-second-owner",
    ],
)
def test_mock_provider_requires_exclusive_captured_owner(tmp_path, sibling):
    (tmp_path / "test_a_sibling.py").write_text(sibling, encoding="utf-8")
    (tmp_path / "test_z_case.py").write_text(
        "from unittest.mock import Mock\ndef test_case():\n    m = Mock()\n    m.assert_not_called()\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    target = [item for item in report["findings"] if item["path"] == "test_z_case.py"]
    assert [item["code"] for item in target] == ["QUALITY_UNKNOWN_TEST_ORACLE"]


def test_mock_provider_allows_unrelated_captured_sibling(tmp_path):
    (tmp_path / "test_a_sibling.py").write_text(
        "def test_sibling():\n    assert 1 == 1\n", encoding="utf-8"
    )
    (tmp_path / "test_z_case.py").write_text(
        "from unittest.mock import Mock\ndef test_case():\n    m = Mock()\n    m.assert_not_called()\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    target = [item for item in report["findings"] if item["path"] == "test_z_case.py"]
    assert [item["code"] for item in target] == ["QUALITY_HOLLOW_TEST"]


def test_mock_provider_ownership_rechecks_changed_sibling_with_cache(tmp_path):
    sibling = tmp_path / "test_a_sibling.py"
    sibling.write_text("def test_sibling():\n    assert True\n", encoding="utf-8")
    (tmp_path / "test_z_case.py").write_text(
        "from unittest.mock import Mock\ndef test_case():\n    m = Mock()\n    m.assert_not_called()\n",
        encoding="utf-8",
    )
    before = security_scan(tmp_path, cache_enabled=True)
    assert any(
        item["path"] == "test_z_case.py" and item["code"] == "QUALITY_HOLLOW_TEST"
        for item in before["findings"]
    )
    sibling.write_text(
        "from unittest.mock import Mock\nMock.assert_not_called = lambda self: None\n",
        encoding="utf-8",
    )
    after = security_scan(tmp_path, cache_enabled=True)
    assert any(
        item["path"] == "test_z_case.py"
        and item["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
        for item in after["findings"]
    )


def test_mock_provider_inventory_fact_binds_source_and_cache(tmp_path):
    from factoryline import type_intent_provider_provenance as provider

    path = tmp_path / "test_case.py"
    manifest = [{"path": "test_case.py", "state": "read"}]
    first = provider.provider_source_inventory(
        tmp_path, {path: b"from unittest.mock import Mock\n"}, manifest
    )
    contexts = {path: {}}
    assert provider.bind_provider_inventory(contexts, first)
    fields = provider.provider_cache_fields(contexts[path])
    assert fields["mock_provider_capability_paths"] == ["test_case.py"]
    second = provider.provider_source_inventory(
        tmp_path, {path: b"from unittest.mock import AsyncMock\n"}, manifest
    )
    provider.bind_provider_inventory(contexts, second)
    assert (
        fields["mock_provider_inventory_sha256"]
        != provider.provider_cache_fields(contexts[path])[
            "mock_provider_inventory_sha256"
        ]
    )
    assert provider._mock_provider_capability in provider.CACHE_HELPERS


@pytest.mark.parametrize(
    "module_name,name",
    [
        ("type_intent_provider_provenance", "_mock_provider_capability"),
        ("type_intent_provider_provenance", "provider_source_inventory"),
        ("type_intent_provider_provenance", "bind_provider_inventory"),
        ("type_intent_provider_provenance", "provider_cache_fields"),
        ("type_intent_hollow", "_captured_unittest_source_closed"),
        ("test_oracle_misuse", "_captured_mock_owner_is_exclusive"),
    ],
)
@pytest.mark.parametrize("mutation", ["binding", "code"])
def test_mock_provider_live_helpers_invalidate_native_cache(
    tmp_path, monkeypatch, module_name, name, mutation
):
    import importlib
    from factoryline import review_audits as scanner

    module = importlib.import_module("factoryline." + module_name)
    original = getattr(module, name)
    before = scanner._oracle_context_cache_key(tmp_path, [], {})

    def replacement(*args, **kwargs):
        return None

    if mutation == "binding":
        monkeypatch.setattr(module, name, replacement)
    else:
        monkeypatch.setattr(original, "__code__", replacement.__code__)
    assert scanner._oracle_context_cache_key(tmp_path, [], {}) != before


@pytest.mark.parametrize("kind", ["Mock", "AsyncMock"])
@pytest.mark.parametrize(
    "calls,assertion,hollow",
    [
        (1, "assert_called_once", True),
        (1, "assert_called", True),
        (2, "assert_called", True),
        (0, "assert_called_once", False),
        (2, "assert_called_once", False),
        (1, "assert_not_called", False),
    ],
)
def test_default_mock_direct_call_count_is_source_proven(
    tmp_path, kind, calls, assertion, hollow
):
    source = f"from unittest.mock import {kind}\ndef test_case():\n    dependency = {kind}()\n"
    source += "    dependency()\n" * calls
    source += f"    dependency.{assertion}()\n"
    (tmp_path / "test_count.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    expected = "QUALITY_HOLLOW_TEST" if hollow else "QUALITY_UNKNOWN_TEST_ORACLE"
    assert report["finding_counts"] == {expected: 1}


@pytest.mark.parametrize(
    "body",
    [
        "dependency(unknown())\n    dependency.assert_called_once()",
        "dependency = other\n    dependency.assert_called_once()",
        "alias = dependency\n    alias()\n    dependency.assert_called_once()",
        "dependency.side_effect = raises\n    dependency()\n    dependency.assert_called_once()",
        "dependency()\n    try:\n        dependency()\n    finally:\n        dependency.assert_called_once()",
        "await dependency()\n    dependency.assert_not_awaited()",
    ],
)
def test_mock_count_requires_closed_direct_nonawaited_calls(tmp_path, body):
    (tmp_path / "test_count.py").write_text(
        "from unittest.mock import AsyncMock\nasync def test_case():\n    dependency = AsyncMock()\n    "
        + body
        + "\n",
        encoding="utf-8",
    )
    assert (
        "QUALITY_HOLLOW_TEST"
        not in security_scan(tmp_path, cache_enabled=False)["finding_counts"]
    )


def test_mock_count_helper_binding_and_code_invalidate_native_cache(
    tmp_path, monkeypatch
):
    from factoryline import review_audits as scanner
    from factoryline import test_oracle_misuse as misuse

    original = misuse._inert_mock_call
    before = scanner._oracle_context_cache_key(tmp_path, [], {})

    def replacement(*args, **kwargs):
        return False

    monkeypatch.setattr(misuse, "_inert_mock_call", replacement)
    assert scanner._oracle_context_cache_key(tmp_path, [], {}) != before
    monkeypatch.setattr(misuse, "_inert_mock_call", original)
    monkeypatch.setattr(original, "__code__", replacement.__code__)
    assert scanner._oracle_context_cache_key(tmp_path, [], {}) != before


@pytest.mark.parametrize(
    "body,hollow",
    [
        (
            "def invoke():\n        dep()\n    invoke()\n    dep.assert_not_called()",
            False,
        ),
        (
            "dep()\n    def invoke():\n        dep()\n    invoke()\n    dep.assert_called_once()",
            False,
        ),
        (
            "def invoke():\n        dep()\n    def wrapper(fn):\n        fn()\n    wrapper(invoke)\n    dep.assert_not_called()",
            False,
        ),
        (
            "def inner():\n        dep()\n    def outer():\n        inner()\n    outer()\n    dep.assert_not_called()",
            False,
        ),
        (
            "def invoke():\n        dep = Mock()\n        dep()\n    invoke()\n    dep.assert_called_once()",
            False,
        ),
        (
            "def invoke():\n        dep()\n    invoke()\n    dep.assert_called_once()",
            True,
        ),
        (
            "def invoke():\n        dep()\n        return\n    invoke()\n    dep.assert_called_once()",
            True,
        ),
        (
            "async def invoke():\n        dep()\n    invoke()\n    dep.assert_not_called()",
            True,
        ),
        (
            "def invoke():\n        pass\n    invoke()\n    dep.assert_not_called()",
            True,
        ),
    ],
    ids=[
        "captured-call-invalidates-not-called",
        "captured-second-call-invalidates-once",
        "callback-captured-call",
        "transitive-captured-call",
        "local-shadow-cannot-overwrite-caller-fact",
        "captured-first-call",
        "captured-call-before-return",
        "unentered-async-body",
        "inert-helper-preserves-state",
    ],
)
def test_mock_call_state_crosses_only_executed_captured_helper_bindings(
    tmp_path, body, hollow
):
    (tmp_path / "test_count.py").write_text(
        "from unittest.mock import Mock\ndef test_case():\n    dep = Mock()\n    "
        + body
        + "\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert ("QUALITY_HOLLOW_TEST" in report["finding_counts"]) is hollow


@pytest.mark.parametrize(
    "name",
    [
        "_source_closed_class_spec",
        "_mock_providers_are_closed",
        "_closed_method_signature",
        "_class_is_unmutated",
        "fixture_registration",
        "direct_mock_return",
        "inert_assertion_methods",
        "fixture_bindings_for_source",
        "_has_wildcard_import",
        "fixtures_for_file",
        "fixture_is_mock",
        "inert_fixture_assertion_reason",
        "inert_fixture_assertions",
        "_root_name",
        "_pytest_fixture_provider_safe",
    ],
)
@pytest.mark.parametrize("mutation", ["binding", "code"])
def test_consolidated_fixture_live_helpers_invalidate_native_cache(
    tmp_path, monkeypatch, name, mutation
):
    from factoryline import mock_fixture_provenance as provider
    from factoryline import review_audits as scanner

    original = getattr(provider, name)
    before = scanner._oracle_context_cache_key(tmp_path, [], {})

    def replacement(*args, **kwargs):
        return None

    if mutation == "binding":
        monkeypatch.setattr(provider, name, replacement)
    else:
        monkeypatch.setattr(original, "__code__", replacement.__code__)
    assert scanner._oracle_context_cache_key(tmp_path, [], {}) != before
