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
