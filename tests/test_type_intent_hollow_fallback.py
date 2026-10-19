import pytest

from factoryline.review_audits import security_scan


def _write_test(tmp_path, source):
    (tmp_path / "test_types.py").write_text(source, encoding="utf-8")


def test_inactive_canonical_assert_type_keeps_concrete_hollow_finding(tmp_path):
    _write_test(
        tmp_path,
        "from typing import assert_type\ndef test_types():\n    assert_type(1, int)\n",
    )

    report = security_scan(tmp_path)

    assert report["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}
    finding = report["findings"][0]
    assert finding["code"] == "QUALITY_HOLLOW_TEST"
    assert finding["severity"] == "MEDIUM"


def test_proven_runtime_assertion_still_suppresses_hollow_finding(tmp_path):
    _write_test(
        tmp_path,
        "from typing import assert_type\n"
        "def test_types():\n"
        "    assert_type(1, int)\n"
        "    assert actual_value == expected_value\n",
    )

    assert security_scan(tmp_path)["finding_counts"] == {}


def test_empty_test_stays_hollow_when_another_function_uses_assert_type(tmp_path):
    _write_test(
        tmp_path,
        "from typing import assert_type\n"
        "def helper():\n    assert_type(1, int)\n"
        "def test_empty():\n    pass\n",
    )

    report = security_scan(tmp_path)

    assert report["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}
    assert report["findings"][0]["facts"]["symbol"] == "test_empty"


def test_noncanonical_same_name_call_is_not_promoted_to_hollow(tmp_path):
    _write_test(
        tmp_path,
        "def assert_type(value, expected):\n    return None\n"
        "def test_types():\n    assert_type(1, int)\n",
    )

    report = security_scan(tmp_path)

    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


def test_rebound_canonical_name_is_not_treated_as_typing_assertion(tmp_path):
    _write_test(
        tmp_path,
        "from typing import assert_type\n"
        "def runtime_assertion(value, expected):\n"
        "    if not isinstance(value, expected):\n"
        "        raise AssertionError('wrong type')\n"
        "assert_type = runtime_assertion\n"
        "def test_types():\n    assert_type(1, int)\n",
    )

    report = security_scan(tmp_path)

    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


def test_delegated_argument_keeps_type_assertion_candidate_unknown(tmp_path):
    _write_test(
        tmp_path,
        "from typing import assert_type\n"
        "def test_types():\n    assert_type(compute_value(), int)\n",
    )

    report = security_scan(tmp_path)

    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


def test_unresolved_delegated_behavior_keeps_unknown_classification(tmp_path):
    _write_test(tmp_path, "def test_delegated():\n    run_behavior()\n")

    report = security_scan(tmp_path)

    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


def test_non_noop_assert_type_replacement_remains_unresolved(tmp_path):
    _write_test(
        tmp_path,
        "import typing\n"
        "def runtime_assertion(value, expected):\n"
        "    if not isinstance(value, expected):\n"
        "        raise AssertionError('wrong type')\n"
        "typing.assert_type = runtime_assertion\n"
        "def test_types():\n    typing.assert_type(1, int)\n",
    )

    report = security_scan(tmp_path)

    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


def test_reflective_provider_replacement_remains_unresolved(tmp_path):
    _write_test(
        tmp_path,
        "import typing\n"
        "def runtime_assertion(value, expected):\n"
        "    if not isinstance(value, expected):\n"
        "        raise AssertionError('wrong type')\n"
        "setattr(typing, 'assert_type', runtime_assertion)\n"
        "def test_types():\n    typing.assert_type(1, int)\n",
    )

    report = security_scan(tmp_path)

    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


def test_provider_alias_escape_remains_unresolved(tmp_path):
    _write_test(
        tmp_path,
        "import typing\n"
        "provider = typing\n"
        "def runtime_assertion(value, expected):\n"
        "    if not isinstance(value, expected):\n"
        "        raise AssertionError('wrong type')\n"
        "setattr(provider, 'assert_type', runtime_assertion)\n"
        "def test_types():\n    typing.assert_type(1, int)\n",
    )

    report = security_scan(tmp_path)

    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


@pytest.mark.parametrize(
    ("module_name", "provider_source", "import_line"),
    [
        (
            "typing",
            "import unittest\n"
            "def assert_type(value, expected):\n"
            "    return getattr(unittest.TestCase(), 'assertIsInstance')(value, expected)\n",
            "from typing import assert_type\n",
        ),
        (
            "typing",
            "def runtime_assertion(value, expected):\n"
            "    return value == expected\n"
            "def assert_type(value, expected):\n"
            "    return runtime_assertion(value, expected)\n",
            "from typing import assert_type\n",
        ),
        (
            "typing_extensions",
            "import unittest\n"
            "def assert_type(value, expected):\n"
            "    return getattr(unittest.TestCase(), 'assertIsInstance')(value, expected)\n",
            "from typing_extensions import assert_type\n",
        ),
        (
            "typing_extensions",
            "def runtime_assertion(value, expected):\n"
            "    return value == expected\n"
            "def assert_type(value, expected):\n"
            "    return runtime_assertion(value, expected)\n",
            "from typing_extensions import assert_type\n",
        ),
    ],
)
def test_local_type_provider_shadow_is_not_credited_as_inert(
    tmp_path, module_name, provider_source, import_line
):
    (tmp_path / f"{module_name}.py").write_text(provider_source, encoding="utf-8")
    _write_test(
        tmp_path,
        import_line + "def test_types():\n    assert_type(1, int)\n",
    )

    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "typing.assert_type = runtime_assertion",
        "setattr(typing, 'assert_type', runtime_assertion)",
    ],
)
def test_captured_imported_module_provider_mutation_remains_unknown(tmp_path, mutation):
    (tmp_path / "patcher.py").write_text(
        "import typing\nimport unittest\n"
        "def runtime_assertion(value, expected):\n"
        "    return getattr(unittest.TestCase(), 'assertIsInstance')(value, expected)\n"
        f"{mutation}\n",
        encoding="utf-8",
    )
    _write_test(
        tmp_path,
        "import patcher\n"
        "from typing import assert_type\n"
        "def test_types():\n    assert_type(1, int)\n",
    )

    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


def test_imported_provider_source_change_invalidates_oracle_context_cache(tmp_path):
    patcher = tmp_path / "patcher.py"
    patcher.write_text(
        "import typing\n"
        "typing.assert_type = lambda value, expected: value == expected\n",
        encoding="utf-8",
    )
    _write_test(
        tmp_path,
        "import patcher\n"
        "from typing import assert_type\n"
        "def test_types():\n    assert_type(1, int)\n",
    )
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }

    patcher.write_text("import typing\n", encoding="utf-8")

    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "acquisition",
    [
        "import sys\nprovider = sys.modules['ty' + 'ping']",
        "import sys as system\nregistry = system\n"
        "provider = registry.modules['ty' + 'ping']",
        "import sys\nbox = [sys]\nprovider = box[0].modules['ty' + 'ping']",
        "import sys\nlookup = getattr\n"
        "provider = lookup(sys, 'modules')['ty' + 'ping']",
        "from importlib import import_module\nprovider = import_module('ty' + 'ping')",
        "import importlib\nloader = importlib\n"
        "provider = loader.import_module('ty' + 'ping')",
        "from builtins import __dict__ as namespace\n"
        "loader = namespace['__import__']\nprovider = loader('ty' + 'ping')",
        "from inspect import currentframe\n"
        "provider = currentframe().f_back.f_globals['typing']",
    ],
)
def test_imported_dynamic_provider_acquisition_remains_unknown(tmp_path, acquisition):
    (tmp_path / "patcher.py").write_text(
        "import unittest\n"
        f"{acquisition}\n"
        "def runtime_assertion(value, expected):\n"
        "    return getattr(unittest.TestCase(), 'assertIsInstance')(value, expected)\n"
        "provider.assert_type = runtime_assertion\n",
        encoding="utf-8",
    )
    _write_test(
        tmp_path,
        "import typing\nimport patcher\nfrom typing import assert_type\n"
        "def test_type():\n    assert_type(1, int)\n",
    )

    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


def test_imported_unrelated_sys_usage_does_not_close_provider_context(tmp_path):
    (tmp_path / "patcher.py").write_text(
        "import sys\nversion = sys.version\n", encoding="utf-8"
    )
    _write_test(
        tmp_path,
        "import patcher\nfrom typing import assert_type\n"
        "def test_type():\n    assert_type(1, int)\n",
    )

    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_imported_reflective_builtin_capability_remains_unknown(tmp_path):
    (tmp_path / "patcher.py").write_text(
        "from builtins import getattr as lookup\n"
        "lookup(object(), 'assert_type', None)\n",
        encoding="utf-8",
    )
    _write_test(
        tmp_path,
        "import patcher\nfrom typing import assert_type\n"
        "def test_type():\n    assert_type(1, int)\n",
    )

    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


@pytest.mark.parametrize(
    "source, expected",
    [
        ("from builtins import __dict__ as ns\nloader = ns['__import__']", True),
        ("from inspect import currentframe\nframe = currentframe()", True),
        ("import inspect\nframe = inspect.currentframe()", True),
        ("from unrelated import exported\nbox = [exported]", True),
        ("from unrelated import *", True),
        ("import sys\nbox = [sys]", True),
        ("import sys\nversion = sys.version", False),
        ("import unrelated\nvalue = 1", False),
    ],
)
def test_type_intent_imported_capability_load_contract(source, expected):
    import ast

    from factoryline.type_intent_dynamic_capability import dynamic_provider_capability

    assert dynamic_provider_capability(ast.parse(source)) is expected
