from __future__ import annotations
import ast
from hashlib import sha256
from pathlib import Path
import pytest
from factoryline.review_audits import security_scan
import json
from factoryline.cli import main
from factoryline.intent_ledger import (
    IntentLedgerError,
    capture_intent_ledger,
    inspect_intent_ledger,
    validate_intent_ledger_record,
)
from factoryline.proof_reuse import record_proof
from factoryline.intent_quality import (
    IntentFinding,
    IntentQualityError,
    assess,
    findings_as_dict,
    normalize,
    require_clear,
)


@pytest.mark.parametrize(
    ("expression", "expected"),
    [("x + 1", 6), ("x - 1", 4), ("x * 2", 10), ("x // 2", 2), ("x % 2", 1)],
)
def test_source_local_integer_arithmetic_is_provably_hollow(
    tmp_path, expression, expected
):
    _write_test(
        tmp_path,
        f"def test_arithmetic():\n    x = 5\n    x = {expression}\n    assert x == {expected}\n",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}
    assert result["findings"][0]["severity"] == "MEDIUM"


@pytest.mark.parametrize(
    "body",
    [
        "x = external(); x = x + 1; assert x == 6",
        "x = 5; x = x / 2; assert x == 2.5",
        "x = 5; x = x // 0",
        "x = 5; x = x % 0",
        "x = 5; x = x ** 1000000000",
        "x = 5; x = x << 1000000000",
        "x = 5; x = x + 1; assert x == 7",
        "x = True; x = x + 1; assert x == 2",
        "x = 'a'; x = x * 1000000000; assert x",
        "x = 340282366920938463463374607431768211455; x = x + 1; assert x",
        "x = 340282366920938463463374607431768211456; x = x - 1; assert x",
        "x = 5; x = x + missing; assert x",
    ],
)
def test_arithmetic_cannot_promote_unproved_or_failing_completion_to_hollow(body):
    from factoryline.test_oracle_misuse import inert_test_completion

    node = ast.parse("def test_arithmetic(): " + body).body[0]
    assert inert_test_completion(node)[0] not in {"NORMAL", "RETURN"}


def test_integer_arithmetic_does_not_invoke_overloaded_operators():
    from factoryline.test_oracle_misuse import _inert_literal

    class UntrustedInteger(int):
        def __add__(self, other):
            raise AssertionError("the scanner executed an overloaded operator")

    expression = ast.parse("x + 1", mode="eval").body
    assert _inert_literal(expression, {"x": UntrustedInteger(5)}) == (False, None)


def test_integer_arithmetic_helper_participates_in_cache_identity():
    from factoryline import test_oracle_misuse as misuse

    assert misuse._inert_integer_arithmetic in misuse.INERT_BODY_HELPERS


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
            "    return getattr(unittest.TestCase(), "
            "'assertIsInstance')(value, expected)\n",
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
            "    return getattr(unittest.TestCase(), "
            "'assertIsInstance')(value, expected)\n",
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


@pytest.mark.parametrize(
    "owner_setup",
    [
        "def anchor(): pass\n"
        "namespace = anchor.__globals__['__builtins__']\n"
        "loader = namespace['__import__']\n"
        "provider = loader('ty' + 'ping')",
        "from inspect import currentframe\n"
        "provider = currentframe().f_globals['__builtins__']['__import__'](\n"
        "    'ty' + 'ping'\n"
        ")",
        "import sys\nbox = [sys]\nprovider = box[0].modules['ty' + 'ping']",
    ],
)
def test_owner_module_provider_capabilities_keep_type_oracle_unknown(
    tmp_path, owner_setup
):
    _write_test(
        tmp_path,
        owner_setup + "\ndef runtime_assertion(value, expected):\n"
        "    assert isinstance(value, expected)\n"
        "provider.assert_type = runtime_assertion\n"
        "from typing import assert_type\n"
        "def test_type():\n    assert_type(1, int)\n",
    )

    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


def test_owner_module_checks_sibling_functions_but_skips_selected_test_body(tmp_path):
    _write_test(
        tmp_path,
        "def inert_helper():\n    pass\n"
        "from typing import assert_type\n"
        "def test_type():\n    assert_type(1, int)\n",
    )

    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_owner_module_non_target_callback_body_keeps_oracle_unknown(tmp_path):
    _write_test(
        tmp_path,
        "def possible_fixture_callback():\n    mutate_provider()\n"
        "from typing import assert_type\n"
        "def test_type():\n    assert_type(1, int)\n",
    )

    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


@pytest.mark.parametrize(
    ("import_line", "call"),
    [
        ("from typing import assert_type", "assert_type"),
        ("from typing import assert_type as check_type", "check_type"),
        ("import typing", "typing.assert_type"),
        ("import typing as type_api", "type_api.assert_type"),
    ],
)
def test_multiple_type_only_tests_keep_individual_hollow_findings(
    tmp_path, import_line, call
):
    _write_test(
        tmp_path,
        f"{import_line}\n"
        f"def test_one():\n    {call}(1, int)\n"
        f"def test_two():\n    {call}(2, int)\n",
    )

    report = security_scan(tmp_path)

    assert report["finding_counts"] == {"QUALITY_HOLLOW_TEST": 2}
    assert {item["facts"]["symbol"] for item in report["findings"]} == {
        "test_one",
        "test_two",
    }


def test_sibling_parameter_shadow_keeps_type_provider_unknown(tmp_path):
    _write_test(
        tmp_path,
        "import typing\n"
        "def helper(typing):\n    typing.assert_type(1, int)\n"
        "def test_type():\n    typing.assert_type(2, int)\n",
    )

    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


@pytest.mark.parametrize(
    ("import_line", "provider_name"),
    [("import typing", "typing"), ("import typing as type_api", "type_api")],
)
def test_module_qualified_type_only_siblings_keep_hollow_findings(
    tmp_path, import_line, provider_name
):
    _write_test(
        tmp_path,
        f"{import_line}\n"
        f"def test_one():\n    {provider_name}.assert_type(1, int)\n"
        f"def test_two():\n    {provider_name}.assert_type(2, int)\n",
    )

    report = security_scan(tmp_path)

    assert report["finding_counts"] == {"QUALITY_HOLLOW_TEST": 2}
    assert {item["facts"]["symbol"] for item in report["findings"]} == {
        "test_one",
        "test_two",
    }


@pytest.mark.parametrize(
    ("import_line", "provider_name", "call"),
    [
        ("from typing import assert_type", "assert_type", "assert_type(1, int)"),
        (
            "from typing import assert_type as check_type",
            "check_type",
            "check_type(1, int)",
        ),
        ("import typing", "typing", "typing.assert_type(1, int)"),
        ("import typing as type_api", "type_api", "type_api.assert_type(1, int)"),
    ],
)
def test_provider_alias_shadowed_by_test_parameter_stays_unknown(
    tmp_path, import_line, provider_name, call
):
    _write_test(
        tmp_path,
        f"{import_line}\ndef test_type({provider_name}):\n    {call}\n",
    )

    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


def test_module_qualified_sibling_runtime_assertion_remains_unknown(tmp_path):
    _write_test(
        tmp_path,
        "import typing\n"
        "def test_type_only():\n    typing.assert_type(1, int)\n"
        "def test_runtime():\n    assert actual == expected\n",
    )

    report = security_scan(tmp_path)

    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}
    assert report["findings"][0]["facts"]["symbol"] == "test_type_only"


def test_mixed_type_only_and_runtime_assertions_preserve_per_test_results(tmp_path):
    _write_test(
        tmp_path,
        "from typing import assert_type\n"
        "def test_type_only():\n    assert_type(1, int)\n"
        "def test_runtime():\n    assert_type(2, int)\n"
        "    assert actual == expected\n",
    )

    report = security_scan(tmp_path)

    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}
    assert report["findings"][0]["facts"]["symbol"] == "test_type_only"


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


@pytest.mark.parametrize(
    ("test_path", "lifecycle_source", "extra_sources"),
    [
        (
            "test_types.py",
            "import typing\n"
            "typing.assert_type = lambda value, expected: value == expected\n",
            {},
        ),
        (
            "nested/test_types.py",
            "import typing\n"
            "typing.assert_type = lambda value, expected: value == expected\n",
            {},
        ),
        (
            "nested/test_types.py",
            "import pytest\n"
            "import typing\n"
            "@pytest.fixture(autouse=True)\n"
            "def patch_provider():\n"
            "    typing.assert_type = lambda value, expected: value == expected\n",
            {},
        ),
        (
            "nested/test_types.py",
            "import pytest\n"
            "import patcher\n"
            "@pytest.fixture(autouse=True)\n"
            "def patch_provider():\n"
            "    patcher.install()\n",
            {
                "patcher.py": "import typing\n"
                "typing.assert_type = lambda value, expected: value == expected\n"
            },
        ),
    ],
)
def test_ancestor_conftest_provider_effects_remain_unknown(
    tmp_path, test_path, lifecycle_source, extra_sources
):
    test_file = tmp_path / test_path
    test_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.write_text(
        "from typing import assert_type\ndef test_types():\n    assert_type(1, int)\n",
        encoding="utf-8",
    )
    conftest = test_file.parent / "conftest.py"
    conftest.write_text(lifecycle_source, encoding="utf-8")
    for relative, source in extra_sources.items():
        (tmp_path / relative).write_text(source, encoding="utf-8")

    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


def test_local_package_initializer_effect_is_in_provider_closure(tmp_path):
    package = tmp_path / "support"
    package.mkdir()
    (package / "__init__.py").write_text(
        "import typing\n"
        "typing.assert_type = lambda value, expected: value == expected\n",
        encoding="utf-8",
    )
    (package / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    _write_test(
        tmp_path,
        "import support.helper\n"
        "from typing import assert_type\n"
        "def test_types():\n    assert_type(1, int)\n",
    )

    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
        ("import typing", False),
        ("import typing as types", False),
        ("import typing\nvalue = typing.version", True),
        ("from typing import assert_type", True),
        ("import unrelated\nvalue = 1", True),
    ],
)
def test_type_intent_imported_capability_load_contract(source, expected):
    import ast

    from factoryline.type_intent_provider_provenance import dynamic_provider_capability

    assert dynamic_provider_capability(ast.parse(source)) is expected


def _completion(source):
    import ast

    from factoryline.test_oracle_misuse import inert_test_completion

    module = ast.parse(source)
    test = next(
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    )
    test._oracle_module = module
    return inert_test_completion(test)


def test_exception_completion_uses_source_local_helper_and_class_identity():
    assert _completion(
        "class CustomError(Exception):\n    pass\n"
        "def operation():\n    pass\n"
        "def test_behavior():\n"
        "    try:\n        operation()\n"
        "    except CustomError:\n        pass\n"
    ) == ("NORMAL", None)


def test_exception_completion_requires_source_for_builtin_identity():
    import ast

    from factoryline.test_oracle_misuse import inert_test_completion

    node = ast.parse(
        "def test_behavior():\n"
        "    try:\n        raise RuntimeError\n"
        "    except RuntimeError:\n        pass\n"
    ).body[0]

    assert inert_test_completion(node) == ("UNKNOWN", None)


def test_exception_completion_accepts_unescaped_qualified_contextlib_provider():
    assert _completion(
        "import contextlib as ctx\n"
        "class CustomError(Exception):\n    pass\n"
        "def test_behavior():\n"
        "    try:\n        with ctx.nullcontext():\n"
        "            raise CustomError()\n"
        "    except CustomError:\n        pass\n"
        "    else:\n        raise RuntimeError\n"
    ) == ("NORMAL", None)


def test_exception_completion_accepts_unescaped_qualified_builtin_provider():
    assert _completion(
        "import builtins as bi\n"
        "def test_behavior():\n"
        "    try:\n        raise bi.RuntimeError\n"
        "    except bi.RuntimeError:\n        pass\n"
    ) == ("NORMAL", None)


def test_assertion_message_helper_return_does_not_return_from_test():
    assert _completion(
        "def test_behavior():\n"
        "    def message():\n        return None\n"
        "    assert False, message()\n"
    ) == ("RAISE", "builtins.AssertionError")


@pytest.mark.parametrize(
    "source",
    [
        "def test_behavior():\n    raise RuntimeError from build_cause()\n",
        "class CustomError(Exception):\n"
        "    def __init__(self):\n        pass\n"
        "def test_behavior():\n"
        "    try:\n        raise CustomError()\n"
        "    except CustomError:\n        pass\n",
        "class CustomError(Exception):\n    pass\n"
        "def test_behavior():\n"
        "    try:\n        raise CustomError()\n"
        "    except (CustomError, dynamic_type()):\n        pass\n",
        "from contextlib import nullcontext\n"
        "class CustomError(Exception):\n    pass\n"
        "def test_behavior():\n"
        "    try:\n        with nullcontext():\n"
        "            raise CustomError()\n"
        "    except CustomError:\n        pass\n"
        "    nullcontext = replacement\n",
        "import contextlib as ctx\n"
        "provider = ctx\n"
        "class CustomError(Exception):\n    pass\n"
        "def test_behavior():\n"
        "    with ctx.nullcontext():\n        raise CustomError()\n",
        "import contextlib as ctx\n"
        "ctx.nullcontext = replacement\n"
        "class CustomError(Exception):\n    pass\n"
        "def test_behavior():\n"
        "    with ctx.nullcontext():\n        raise CustomError()\n",
        "def test_behavior():\n"
        "    try:\n        assert False, run_oracle()\n"
        "    except AssertionError:\n        pass\n",
        "def test_behavior():\n"
        "    x = True\n    try:\n        x = False\n"
        "    finally:\n        if x:\n            pass\n"
        "        else:\n            run_oracle()\n",
        "def test_behavior():\n"
        "    x = True\n    try:\n        x = False\n"
        "    except Exception:\n        pass\n    else:\n"
        "        if x:\n            pass\n        else:\n"
        "            run_oracle()\n",
        "import builtins\n"
        "builtins.RuntimeError = lambda: run_oracle()\n"
        "def test_behavior():\n    RuntimeError()\n",
        "import contextlib\n"
        "contextlib.nullcontext = lambda: run_oracle()\n"
        "from contextlib import nullcontext\n"
        "def test_behavior():\n    with nullcontext():\n        pass\n",
        "import builtins\n"
        "builtins.Exception = opaque_base\n"
        "class CustomError(Exception):\n    pass\n"
        "def test_behavior():\n"
        "    try:\n        raise CustomError()\n"
        "    except CustomError:\n        pass\n",
        "def test_behavior():\n"
        "    def helper():\n        pass\n"
        "    try:\n        def helper():\n            run_oracle()\n"
        "    except Exception:\n        pass\n    else:\n        helper()\n",
        '__builtins__["RuntimeError"] = lambda: run_oracle()\n'
        "def test_behavior():\n    RuntimeError()\n",
    ],
)
def test_exception_completion_keeps_unproved_identity_unknown(source):
    assert _completion(source) == ("UNKNOWN", None)


@pytest.mark.parametrize(
    "assertion",
    [
        "self.assertTrue(True)",
        "self.assertFalse(False)",
        "self.assertEqual(1, 1)",
        "self.assertTupleEqual((1,), (1,))",
        "self.assertListEqual([1], [1])",
    ],
)
def test_source_proven_unittest_literal_assertions_are_hollow(tmp_path, assertion):
    _write_test(
        tmp_path,
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        f"        {assertion}\n",
    )

    report = security_scan(tmp_path)

    assert report["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_source_proven_unittest_alias_import_is_hollow(tmp_path):
    _write_test(
        tmp_path,
        "import unittest as unit\n"
        "class Checks(unit.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertEqual((1,), (1,))\n",
    )

    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "source",
    [
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertEqual(value, value)\n",
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(compute())\n",
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertEqual(1, 2)\n",
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def assertTrue(self, value):\n        pass\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n",
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def setUp(self):\n        pass\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n",
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def tearDown(self):\n        pass\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n",
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def __getattribute__(self, name):\n        return object.__getattribute__(self, name)\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n",
        "import unittest\n"
        "@decorate\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n",
        "import unittest\n"
        "class Checks(unittest.TestCase, Mixin):\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n",
        "import unittest\n"
        "class Checks(unittest.TestCase, metaclass=Meta):\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n",
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self, value=True):\n"
        "        self.assertTrue(True)\n",
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    @decorate\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n",
        "import unittest\n"
        "unittest.TestCase.assertTrue = lambda self, value: None\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n",
        "import unittest\n"
        "setattr(unittest.TestCase, 'assertTrue', lambda self, value: None)\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n",
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue = replacement\n"
        "        self.assertTrue(True)\n",
        "from unittest import TestCase\n"
        "class Checks(TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n",
    ],
)
def test_unclosed_unittest_literal_sources_are_not_promoted(tmp_path, source):
    _write_test(tmp_path, source)

    assert "QUALITY_HOLLOW_TEST" not in security_scan(tmp_path)["finding_counts"]


def test_local_unittest_source_provider_is_not_credited(tmp_path):
    (tmp_path / "unittest.py").write_text("class TestCase: pass\n", encoding="utf-8")
    _write_test(
        tmp_path,
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n",
    )

    assert "QUALITY_HOLLOW_TEST" not in security_scan(tmp_path)["finding_counts"]


def test_conftest_unittest_provider_mutation_is_not_credited(tmp_path):
    (tmp_path / "conftest.py").write_text(
        "import unittest\nunittest.TestCase.assertTrue = lambda self, value: None\n",
        encoding="utf-8",
    )
    _write_test(
        tmp_path,
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n",
    )

    assert "QUALITY_HOLLOW_TEST" not in security_scan(tmp_path)["finding_counts"]


def test_new_unittest_proof_helpers_are_in_the_cache_epoch():
    from factoryline import type_intent_hollow

    assert (
        type_intent_hollow.source_proven_unittest_vacuity
        in type_intent_hollow.CACHE_HELPERS
    )


def _bound_unittest_test_node(source, relative="tests/test_fixture.py"):
    from factoryline import type_intent_hollow

    raw = source.encode("utf-8")
    root = Path("C:/captured")
    module = ast.parse(raw)
    node = next(
        item
        for item in ast.walk(module)
        if isinstance(item, ast.FunctionDef) and item.name == "test_behavior"
    )
    module._security_oracle_context = {
        "provider_source_inventory_complete": True,
        "provider_source_closure_complete": True,
        "provider_source_closure": [],
        "provider_owner_local_imports": [],
    }
    module._security_source_context = (root, {root / relative: raw})
    module._oracle_source_sha256 = sha256(raw).hexdigest()
    module._oracle_source_lines = raw.decode("utf-8").splitlines()
    node._oracle_module = module
    return type_intent_hollow, module, node, root, raw


@pytest.mark.parametrize("mutation", ["literal", "class_base", "import"])
def test_unittest_proof_rejects_ast_mutation_after_source_capture(mutation):
    source = (
        "import unittest as unit\n"
        "class Checks(unit.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertEqual(1, 1)\n"
    )
    proof, module, _node, _root, _raw = _bound_unittest_test_node(source)
    class_node = next(item for item in module.body if isinstance(item, ast.ClassDef))
    method = next(item for item in class_node.body if isinstance(item, ast.FunctionDef))
    if mutation == "literal":
        method.body[0].value.args[1].value = 2
    elif mutation == "class_base":
        class_node.bases[0].attr = "OtherCase"
    else:
        module.body[0].names[0].name = "other"

    assert not proof.source_proven_unittest_vacuity(method)


def test_unittest_proof_requires_unchanged_captured_bytes():
    source = (
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n"
    )
    proof, module, node, root, _raw = _bound_unittest_test_node(source)
    module._security_source_context = (
        root,
        {
            root / "tests/test_fixture.py": source.replace("True", "False").encode(
                "utf-8"
            )
        },
    )

    assert not proof.source_proven_unittest_vacuity(node)


def test_unittest_proof_rejects_ambiguous_matching_source_path():
    source = (
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n"
    )
    proof, module, node, root, raw = _bound_unittest_test_node(source)
    module._security_source_context = (
        root,
        {
            root / "tests/test_fixture.py": raw,
            root / "unrelated.py": raw,
        },
    )

    assert not proof.source_proven_unittest_vacuity(node)


def test_unittest_proof_rejects_cloned_method_not_owned_by_module():
    import copy

    source = (
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertTrue(True)\n"
    )
    proof, module, node, _root, _raw = _bound_unittest_test_node(source)
    clone = copy.deepcopy(node)
    clone._oracle_module = module

    assert not proof.source_proven_unittest_vacuity(clone)


@pytest.mark.parametrize(
    "body",
    [
        "pass",
        '"helper docs"\n    pass',
        '"helper docs"',
        "...",
        "return",
        "return None",
        '"helper docs"\n    return None',
    ],
)
def test_closed_module_stub_helper_is_hollow(tmp_path, body):
    _write_test(
        tmp_path,
        "def local_pure():\n    " + body + "\ndef test_behavior():\n    local_pure()\n",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}
    assert report["findings"][0]["severity"] == "MEDIUM"


@pytest.mark.parametrize(
    "setup",
    [
        "from external import *\n",
        "local_pure = replacement\n",
        "alias = local_pure\n",
        "local_pure.__code__ = replacement.__code__\n",
    ],
)
def test_module_stub_binding_must_remain_closed(tmp_path, setup):
    _write_test(
        tmp_path,
        'def local_pure():\n    "helper docs"\n    pass\n'
        + setup
        + "def test_behavior():\n    local_pure()\n",
    )
    assert "QUALITY_HOLLOW_TEST" not in security_scan(tmp_path)["finding_counts"]


@pytest.mark.parametrize(
    "helper",
    [
        "def local_pure():\n    assert False\n",
        "def local_pure():\n    unknown()\n",
        "async def local_pure():\n    pass\n",
        "@decorate\ndef local_pure():\n    pass\n",
        "def local_pure(required):\n    pass\n",
    ],
)
def test_unproved_module_helper_is_not_hollow(tmp_path, helper):
    _write_test(tmp_path, helper + "def test_behavior():\n    local_pure()\n")
    # A source-bound async call only creates a coroutine; other bodies can raise or escape.
    expected_hollow = helper.startswith("async def ")
    report = security_scan(tmp_path)
    assert ("QUALITY_HOLLOW_TEST" in report["finding_counts"]) is expected_hollow


# --- Merged from test_intent_ledger.py; test definitions and fixtures retained ---


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _capture(root: Path, changed: list[str] | None = None) -> dict:
    return capture_intent_ledger(
        root,
        change_list="Billing cancellation",
        changed=changed or ["app/billing.py"],
        confirmed_by="Ada",
        promise="Cancelled accounts never receive a new invoice.",
        non_goal="This change does not migrate historical invoices.",
        failure_case="A cancelled account receiving an invoice must fail the declared negative proof.",
        confirmation="CAPTURE Billing cancellation",
    )


def _review(
    *, paths: list[str], stale: list[str] | None = None, coverage: bool = True
) -> dict:
    return {
        "input_source": "explicit",
        "changed_paths": paths,
        "review_sha256": "a" * 64,
        "unproven_claims": [],
        "coverage": {"ok": coverage, "uncovered": ["REQ-1"] if not coverage else []},
        "impact": {
            "rerun_proofs": [{"proof_id": item} for item in stale or []],
            "unmatched_changed_paths": [],
        },
    }


def test_capture_records_only_confirmed_local_metadata(tmp_path: Path) -> None:
    result = _capture(tmp_path)

    assert result["marker"] == "INTENT_LEDGER_CAPTURED"
    assert result["authority"]["record_write"] is True
    assert all(
        value is False
        for key, value in result["authority"].items()
        if key != "record_write"
    )
    path = tmp_path / result["path"]
    assert path.is_file()
    assert (
        validate_intent_ledger_record(json.loads(path.read_text(encoding="utf-8")))
        == result["record"]
    )


def test_capture_rejects_missing_exact_confirmation_without_writing(
    tmp_path: Path,
) -> None:
    before = _files(tmp_path)
    with pytest.raises(IntentLedgerError) as exc:
        capture_intent_ledger(
            tmp_path,
            change_list="Billing cancellation",
            changed=["app/billing.py"],
            confirmed_by="Ada",
            promise="Promise",
            non_goal="Non-goal",
            failure_case="Failure case",
            confirmation="yes",
        )
    assert exc.value.code == "INTENT_LEDGER_CONFIRMATION_REQUIRED"
    assert _files(tmp_path) == before


def test_capture_rejects_vague_promise_even_with_exact_confirmation(
    tmp_path: Path,
) -> None:
    with pytest.raises(IntentLedgerError) as exc:
        capture_intent_ledger(
            tmp_path,
            change_list="Billing cancellation",
            changed=["app/billing.py"],
            confirmed_by="Ada",
            promise="Make it better.",
            non_goal="No historical migration.",
            failure_case="A cancelled account receiving an invoice fails.",
            confirmation="CAPTURE Billing cancellation",
        )
    assert exc.value.code == "INTENT_LEDGER_INTENT_UNCLEAR"
    assert not (tmp_path / ".factory" / "intent-ledgers").exists()


def test_inspection_is_read_only_and_returns_uncontracted_without_inventing_intent(
    tmp_path: Path,
) -> None:
    before = _files(tmp_path)
    inspection = inspect_intent_ledger(
        tmp_path, change_list="Billing cancellation", changed=["app/billing.py"]
    )

    assert inspection["state"] == "uncontracted"
    assert inspection["next_action"]["action"] == "capture_intent"
    assert inspection["record"] is None
    assert inspection["authority"]["record_write"] is False
    assert all(value is False for value in inspection["authority"].values())
    assert _files(tmp_path) == before


def test_scope_escape_precedes_lower_priority_change_review_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _capture(tmp_path)
    monkeypatch.setattr(
        "factoryline.intent_ledger.review_change",
        lambda *_args, **_kwargs: _review(
            paths=["app/billing.py", "app/invoices.py"],
            stale=["proof-1"],
            coverage=False,
        ),
    )

    inspection = inspect_intent_ledger(
        tmp_path,
        change_list="Billing cancellation",
        changed=["app/billing.py", "app/invoices.py"],
    )

    assert inspection["state"] == "scope_escape"
    assert inspection["findings"][0]["facts"]["paths"] == ["app/invoices.py"]
    assert inspection["next_action"]["action"] == "amend_or_split_change_list"


def test_stale_proof_uses_existing_change_review_without_executing_a_gate(
    tmp_path: Path,
) -> None:
    (tmp_path / "input.txt").write_text("before", encoding="utf-8")
    (tmp_path / "output.txt").write_text("green", encoding="utf-8")
    record_proof(
        tmp_path,
        {
            "name": "unit",
            "command": ["python", "-m", "pytest"],
            "read_only": True,
            "inputs": ["input.txt"],
            "outputs": ["output.txt"],
        },
        elapsed_ms=50,
    )
    (tmp_path / "input.txt").write_text("after", encoding="utf-8")
    _capture(tmp_path, ["input.txt"])
    before = _files(tmp_path)

    inspection = inspect_intent_ledger(
        tmp_path, change_list="Billing cancellation", changed=["input.txt"]
    )

    assert inspection["state"] == "stale_proof"
    assert inspection["next_action"]["action"] == "rerun_stale_proof"
    assert inspection["change_review"]["stale_proof_ids"]
    assert _files(tmp_path) == before


def test_coverage_gap_and_ready_state_are_deterministic_from_explicit_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _capture(tmp_path)
    monkeypatch.setattr(
        "factoryline.intent_ledger.review_change",
        lambda *_args, **_kwargs: _review(paths=["app/billing.py"], coverage=False),
    )
    gap = inspect_intent_ledger(
        tmp_path, change_list="Billing cancellation", changed=["app/billing.py"]
    )
    assert gap["state"] == "coverage_incomplete"

    monkeypatch.setattr(
        "factoryline.intent_ledger.review_change",
        lambda *_args, **_kwargs: _review(paths=["app/billing.py"]),
    )
    ready = inspect_intent_ledger(
        tmp_path, change_list="Billing cancellation", changed=["app/billing.py"]
    )
    assert ready["state"] == "ready_for_human_review"
    assert ready["next_action"]["action"] == "review_packet"
    assert (
        inspect_intent_ledger(
            tmp_path, change_list="Billing cancellation", changed=["app/billing.py"]
        )["inspection_sha256"]
        == ready["inspection_sha256"]
    )


def test_latest_tampered_record_fails_closed_without_fallback(tmp_path: Path) -> None:
    first = _capture(tmp_path)
    second = _capture(tmp_path)
    assert first["path"] != second["path"]
    (tmp_path / second["path"]).write_text("{}", encoding="utf-8")

    inspection = inspect_intent_ledger(
        tmp_path, change_list="Billing cancellation", changed=["app/billing.py"]
    )

    assert inspection["state"] == "intent_ledger_invalid"
    assert inspection["record"] is None
    assert inspection["record_path"] == second["path"]


def test_identical_clock_tick_captures_never_overwrite_each_other(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("factoryline.intent_ledger.time.time_ns", lambda: 42)

    first = _capture(tmp_path)
    second = _capture(tmp_path)

    assert first["path"] != second["path"]
    assert (tmp_path / first["path"]).is_file()
    assert (tmp_path / second["path"]).is_file()
    assert len(list((tmp_path / ".factory" / "intent-ledgers").glob("*.json"))) == 2


def test_cli_capture_and_read_only_inspection_are_machine_readable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capture_args = [
        "intent",
        "capture",
        "--root",
        str(tmp_path),
        "--change-list",
        "Billing cancellation",
        "--changed",
        "app/billing.py",
        "--confirmed-by",
        "Ada",
        "--promise",
        "Cancelled accounts never receive a new invoice.",
        "--non-goal",
        "No historical migration.",
        "--failure-case",
        "Invoice creation for a cancelled account fails.",
        "--confirmation",
        "CAPTURE Billing cancellation",
        "--json",
    ]
    assert main(capture_args) == 0
    captured = json.loads(capsys.readouterr().out)
    before = _files(tmp_path)

    assert (
        main(
            [
                "intent",
                "inspect",
                "--root",
                str(tmp_path),
                "--change-list",
                "Billing cancellation",
                "--changed",
                "app/billing.py",
                "--json",
            ]
        )
        == 0
    )
    inspection = json.loads(capsys.readouterr().out)
    assert captured["marker"] == "INTENT_LEDGER_CAPTURED"
    assert inspection["state"] in {
        "coverage_incomplete",
        "scope_escape",
        "ready_for_human_review",
    }
    assert _files(tmp_path) == before


# --- Merged from test_intent_quality.py; test definitions and fixtures retained ---


def test_normalize_and_findings_as_dict_preserve_text_and_emit_stable_diagnostics():
    assert normalize("  A reviewer\n checks   the receipt. ") == (
        "A reviewer checks the receipt."
    )
    assert normalize(None) == ""

    findings = findings_as_dict("Make it better", field="acceptance")

    assert findings == [
        {
            "code": "INTENT_VAGUE_LANGUAGE",
            "message": "acceptance contains vague phrase: make_it_better",
        },
        {
            "code": "INTENT_NO_ACTION",
            "message": "acceptance does not state an observable action or state transition",
        },
    ]
    assert IntentFinding("INTENT_NO_ACTION", "missing action").as_dict() == {
        "code": "INTENT_NO_ACTION",
        "message": "missing action",
    }


def test_intent_quality_accepts_concrete_action_and_observation() -> None:
    text, findings = assess(
        "A reviewer can create a hash-bound receipt.",
        field="intent",
        require_observable=True,
    )
    assert text == "A reviewer can create a hash-bound receipt."
    assert findings == []


@pytest.mark.parametrize(
    "value, field, observable, code",
    [
        ("Make it better", "intent", False, "INTENT_VAGUE_LANGUAGE"),
        ("TODO", "intent", False, "INTENT_PLACEHOLDER"),
        ("Fine", "intent", False, "INTENT_NO_ACTION"),
        ("Do something", "acceptance", True, "INTENT_VAGUE_LANGUAGE"),
        ("The task runs", "acceptance", True, "INTENT_NOT_OBSERVABLE"),
    ],
)
def test_intent_quality_rejects_unverifiable_language(
    value: str, field: str, observable: bool, code: str
) -> None:
    with pytest.raises(IntentQualityError, match=code):
        require_clear(value, field=field, require_observable=observable)


@pytest.mark.parametrize(
    ("import_statement", "call_expression", "expected"),
    [
        (
            "import unittest.mock\n",
            "unittest.mock.MagicMock()",
            "unittest.mock.MagicMock",
        ),
        (
            "import unittest.mock as mock\n",
            "mock.MagicMock()",
            "unittest.mock.MagicMock",
        ),
        (
            "from unittest import mock\n",
            "mock.MagicMock()",
            "unittest.mock.MagicMock",
        ),
        (
            "from unittest.mock import MagicMock as Mock\n",
            "Mock()",
            "unittest.mock.MagicMock",
        ),
        (
            "import xml.etree.ElementTree\n",
            "xml.etree.ElementTree.fromstring(data)",
            "xml.etree.ElementTree.fromstring",
        ),
        ("import pickle\n", "pickle.loads(data)", "pickle.loads"),
        (
            "import pickle as serializer\n",
            "serializer.loads(data)",
            "pickle.loads",
        ),
    ],
)
def test_import_aliases_follow_python_binding_semantics(
    import_statement: str, call_expression: str, expected: str
) -> None:
    from factoryline.review_audits import (
        _module_security_aliases,
        _normalized_call_name,
        _scope_security_aliases,
    )

    tree = ast.parse(import_statement + f"def test_case():\n    {call_expression}\n")
    scope = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "test_case"
    )
    call = next(node for node in ast.walk(scope) if isinstance(node, ast.Call))
    aliases = _scope_security_aliases(_module_security_aliases(tree), scope)

    assert _normalized_call_name(call, aliases) == expected


@pytest.mark.parametrize(
    ("import_statement", "binding", "call_expression"),
    [
        (
            "import unittest.mock\n",
            "unittest",
            "unittest.mock.MagicMock()",
        ),
        (
            "import unittest.mock as mock\n",
            "mock",
            "mock.MagicMock()",
        ),
        (
            "from unittest import mock\n",
            "mock",
            "mock.MagicMock()",
        ),
    ],
)
def test_import_aliases_are_invalidated_by_local_rebinding(
    import_statement: str, binding: str, call_expression: str
) -> None:
    from factoryline.review_audits import (
        _module_security_aliases,
        _normalized_call_name,
        _scope_security_aliases,
    )

    tree = ast.parse(
        import_statement
        + f"def test_case():\n    {binding} = replacement\n    {call_expression}\n"
    )
    scope = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "test_case"
    )
    call = next(node for node in ast.walk(scope) if isinstance(node, ast.Call))
    aliases = _scope_security_aliases(_module_security_aliases(tree), scope)

    assert binding not in aliases
    assert _normalized_call_name(call, aliases) == call_expression.removesuffix("()")


def test_local_dotted_import_rebinds_the_top_level_package_after_shadowing() -> None:
    from factoryline.review_audits import (
        _normalized_call_name,
        _scope_security_aliases,
    )

    tree = ast.parse(
        "def test_case():\n"
        "    unittest = replacement\n"
        "    import unittest.mock\n"
        "    unittest.mock.MagicMock()\n"
    )
    scope = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    call = next(node for node in ast.walk(scope) if isinstance(node, ast.Call))
    aliases = _scope_security_aliases({}, scope)

    assert aliases["unittest"] == "unittest"
    assert _normalized_call_name(call, aliases) == "unittest.mock.MagicMock"


@pytest.mark.parametrize(
    "case, source, rule, expected",
    [
        (
            "open_raw",
            "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    name = request.args.get('filename')\n    open(os.path.join('/srv/uploads', name), 'wb')\n",
            "SECURITY_PATH_TRAVERSAL",
            True,
        ),
        (
            "open_exact_return_fixed_root",
            "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    name = secure_filename(request.args.get('filename'))\n    open(os.path.join('/srv/uploads', name), 'wb')\n",
            "SECURITY_PATH_TRAVERSAL",
            False,
        ),
        (
            "open_sibling_unsanitized",
            "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    raw = request.args.get('filename')\n    clean = secure_filename(raw)\n    open(os.path.join('/srv/uploads', raw), 'wb')\n",
            "SECURITY_PATH_TRAVERSAL",
            True,
        ),
        (
            "open_later_rebind",
            "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    name = secure_filename(request.args.get('filename'))\n    name = request.args.get('other')\n    open(os.path.join('/srv/uploads', name), 'wb')\n",
            "SECURITY_PATH_TRAVERSAL",
            True,
        ),
        (
            "open_custom_same_name",
            "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    def secure_filename(value):\n        return value\n    name = secure_filename(request.args.get('filename'))\n    open(os.path.join('/srv/uploads', name), 'wb')\n",
            "SECURITY_PATH_TRAVERSAL",
            True,
        ),
        (
            "upload_fixed_root",
            "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    file = request.files['file']\n    file.save(os.path.join('/srv/uploads', secure_filename(file.filename)))\n",
            "SECURITY_PATH_TRAVERSAL",
            False,
        ),
        (
            "upload_tainted_root",
            "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    file = request.files['file']\n    file.save(os.path.join(request.args.get('root'), secure_filename(file.filename)))\n",
            "SECURITY_PATH_TRAVERSAL",
            True,
        ),
        (
            "upload_ignore_return",
            "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    file = request.files['file']\n    secure_filename(file.filename)\n    file.save(os.path.join('/srv/uploads', file.filename))\n",
            "SECURITY_PATH_TRAVERSAL",
            True,
        ),
        (
            "upload_module_replaced",
            "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    import werkzeug.utils\n    werkzeug.utils.secure_filename = lambda value: value\n    file = request.files['file']\n    file.save(os.path.join('/srv/uploads', werkzeug.utils.secure_filename(file.filename)))\n",
            "SECURITY_PATH_TRAVERSAL",
            True,
        ),
        (
            "upload_return_rebind",
            "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    file = request.files['file']\n    leaf = secure_filename(file.filename)\n    leaf = file.filename\n    file.save(os.path.join('/srv/uploads', leaf))\n",
            "SECURITY_PATH_TRAVERSAL",
            True,
        ),
        (
            "upload_branch_mismatch",
            "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    file = request.files['file']\n    if request.args.get('safe'):\n        leaf = secure_filename(file.filename)\n    else:\n        leaf = file.filename\n    file.save(os.path.join('/srv/uploads', leaf))\n",
            "SECURITY_PATH_TRAVERSAL",
            True,
        ),
        (
            "url_positional",
            'from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url = request.args.get("url")\n    requests.get(url)\n',
            "SECURITY_SSRF",
            True,
        ),
        (
            "url_keyword",
            'from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url = request.args.get("url")\n    requests.get(url=url)\n',
            "SECURITY_SSRF",
            True,
        ),
        (
            "url_guard_true",
            "from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url = request.args.get(\"url\")\n    if urllib.parse.urlparse(url).hostname in {'example.test'}:\n        requests.get(url)\n",
            "SECURITY_SSRF",
            False,
        ),
        (
            "url_guard_else",
            "from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url = request.args.get(\"url\")\n    if urllib.parse.urlparse(url).hostname in {'example.test'}:\n        pass\n    else:\n        requests.get(url)\n",
            "SECURITY_SSRF",
            True,
        ),
        (
            "url_guard_other",
            "from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url = request.args.get(\"url\")\n    other = request.args.get('other')\n    if urllib.parse.urlparse(other).hostname in {'example.test'}:\n        requests.get(url)\n",
            "SECURITY_SSRF",
            True,
        ),
        (
            "url_guard_rebind",
            "from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url = request.args.get(\"url\")\n    if urllib.parse.urlparse(url).hostname in {'example.test'}:\n        url = request.args.get('other')\n        requests.get(url)\n",
            "SECURITY_SSRF",
            True,
        ),
        (
            "url_custom_parser",
            "from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url = request.args.get(\"url\")\n    def fake_parse(value):\n        return type('URL', (), {'hostname':'example.test'})()\n    urllib.parse.urlparse = fake_parse\n    if urllib.parse.urlparse(url).hostname in {'example.test'}:\n        requests.get(url)\n",
            "SECURITY_SSRF",
            True,
        ),
        (
            "sql_interpolated_positional",
            'from flask import request\nimport psycopg\ndef view():\n    conn = psycopg.connect("dbname=app")\n    cursor = conn.cursor()\n    name = request.args.get("name")\n    cursor.execute(\'SELECT * FROM users WHERE name=\' + name)\n',
            "SECURITY_SQL_INJECTION",
            True,
        ),
        (
            "sql_interpolated_keyword",
            'from flask import request\nimport psycopg\ndef view():\n    conn = psycopg.connect("dbname=app")\n    cursor = conn.cursor()\n    name = request.args.get("name")\n    cursor.execute(query=\'SELECT * FROM users WHERE name=\' + name)\n',
            "SECURITY_SQL_INJECTION",
            True,
        ),
        (
            "sql_bound_parameter",
            'from flask import request\nimport psycopg\ndef view():\n    conn = psycopg.connect("dbname=app")\n    cursor = conn.cursor()\n    name = request.args.get("name")\n    cursor.execute(\'SELECT * FROM users WHERE name=%s\', (name,))\n',
            "SECURITY_SQL_INJECTION",
            False,
        ),
        (
            "sql_bound_parameter_keyword",
            'from flask import request\nimport psycopg\ndef view():\n    conn = psycopg.connect("dbname=app")\n    cursor = conn.cursor()\n    name = request.args.get("name")\n    cursor.execute(query=\'SELECT * FROM users WHERE name=%s\', params=(name,))\n',
            "SECURITY_SQL_INJECTION",
            False,
        ),
        (
            "sql_tainted_query_with_params",
            'from flask import request\nimport psycopg\ndef view():\n    conn = psycopg.connect("dbname=app")\n    cursor = conn.cursor()\n    name = request.args.get("name")\n    cursor.execute(\'SELECT * FROM users ORDER BY \' + name, ())\n',
            "SECURITY_SQL_INJECTION",
            True,
        ),
        (
            "open_keyword_file",
            "from flask import request\ndef view():\n    open(file=request.args.get('path'))\n",
            "SECURITY_PATH_TRAVERSAL",
            True,
        ),
        (
            "url_sibling_params",
            "from flask import request\nimport requests\ndef view():\n    requests.get('https://example.test', params={'next':request.args.get('url')})\n",
            "SECURITY_SSRF",
            False,
        ),
        (
            "os_path_parent_replaced",
            'from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\nfrom types import SimpleNamespace\nos.path=SimpleNamespace(join=lambda root,leaf: request.args.get("path"))\ndef view():\n    leaf=secure_filename(request.args.get("filename"))\n    open(os.path.join("/srv/uploads",leaf),"wb")\n',
            "SECURITY_PATH_TRAVERSAL",
            True,
        ),
        (
            "urllib_parse_parent_replaced",
            'from flask import request\nimport requests\nimport urllib.parse\nfrom types import SimpleNamespace\nurllib.parse=SimpleNamespace(urlparse=lambda value: SimpleNamespace(hostname="example.test"))\ndef view():\n    url=request.args.get("url")\n    if urllib.parse.urlparse(url).hostname in {"example.test"}:\n        requests.get(url=url)\n',
            "SECURITY_SSRF",
            True,
        ),
        (
            "werkzeug_utils_parent_replaced",
            'from flask import request\nimport werkzeug.utils\nimport os\nfrom types import SimpleNamespace\nwerkzeug.utils=SimpleNamespace(secure_filename=lambda value:value)\ndef view():\n    leaf=werkzeug.utils.secure_filename(request.args.get("filename"))\n    open(os.path.join("/srv/uploads",leaf),"wb")\n',
            "SECURITY_PATH_TRAVERSAL",
            True,
        ),
        (
            "url_keyword_rebind_during_evaluation",
            'from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url=request.args.get("url")\n    if urllib.parse.urlparse(url).hostname in {"example.test"}:\n        requests.get(params=(url := request.args.get("other")),url=url)\n',
            "SECURITY_SSRF",
            True,
        ),
        (
            "sanitized_leaf_augmented_with_raw",
            'from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    leaf=secure_filename(request.args.get("filename"))\n    leaf += request.args.get("suffix")\n    open(os.path.join("/srv/uploads",leaf),"wb")\n',
            "SECURITY_PATH_TRAVERSAL",
            True,
        ),
        (
            "bound-secure-filename-import-alias",
            "from flask import request\nfrom werkzeug.utils import secure_filename\ndef save_upload():\n    clean = secure_filename\n    uploaded = request.files['file']\n    uploaded.save('/uploads/' + clean(uploaded.filename))\n",
            "SECURITY_PATH_TRAVERSAL",
            False,
        ),
    ],
)
def test_security_sink_slots_and_exact_sanitizer_results(
    tmp_path, case, source, rule, expected
):
    from factoryline.review_audits import security_scan

    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    matching = [finding for finding in result["findings"] if finding["code"] == rule]
    assert bool(matching) is expected, (case, result)
    if expected:
        assert all(finding["severity"] == "HIGH" for finding in matching)


def test_sanitizer_provider_cache_is_invalidated_at_scope_binding():
    from factoryline.review_integrity import (
        _security_proven_callee,
        bind_security_call_scopes,
    )

    tree = ast.parse(
        "import urllib.parse\ndef f(url):\n    return urllib.parse.urlparse(url)\n"
    )
    call = tree.body[1].body[0].value
    aliases = {"urllib": "urllib"}
    bind_security_call_scopes(tree)
    assert _security_proven_callee(call, aliases, "urllib.parse.urlparse")
    tree.body.insert(1, ast.parse("urllib.parse.urlparse = replacement").body[0])
    bind_security_call_scopes(tree)
    assert not _security_proven_callee(call, aliases, "urllib.parse.urlparse")


def test_url_guard_does_not_survive_sibling_argument_effect(tmp_path):
    from factoryline.review_audits import security_scan

    (tmp_path / "app.py").write_text(
        "from flask import request\nimport requests\nimport urllib.parse\n"
        "def view():\n    url = request.args.get('url')\n"
        "    def change_url():\n        nonlocal url\n"
        "        url = request.args.get('other')\n"
        "    if urllib.parse.urlparse(url).hostname in {'example.test'}:\n"
        "        requests.get(params=change_url(), url=url)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert any(row["code"] == "SECURITY_SSRF" for row in result["findings"])


@pytest.mark.parametrize(
    "source",
    [
        "import sqlalchemy as sa\nx = 1\n",
        "import sqlalchemy as sa\ndef f(sa):\n    return sa\n",
        "import sqlalchemy as sa\nfrom other import *\n",
        "import sqlalchemy as sa\nimport sqlalchemy as sa\n",
        "import sqlalchemy as sa\ndef f():\n    import other as sa\n",
        "import sqlalchemy as sa\nclass sa: pass\n",
    ],
)
def test_db_symbol_inventory_is_local_and_preserves_shadowing(source, monkeypatch):
    from factoryline import intent_quality as contracts

    tree = ast.parse(source)
    original_walk = ast.walk
    nodes = tuple(original_walk(tree))
    symbols = {}
    seen = {}
    counts = {}
    for node in tree.body:
        for local, qualified in contracts._db_import_bindings(node):
            seen[local] = seen.get(local, 0) + 1
            symbols[local] = qualified
    for node in nodes:
        for local in contracts._db_python_import_names(node):
            counts[local] = counts.get(local, 0) + 1
    bound = (
        set(symbols)
        if any(
            isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
            for n in nodes
        )
        else set()
    )
    bound.update(
        n.id for n in nodes if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
    )
    bound.update(n.arg for n in nodes if isinstance(n, ast.arg))
    bound.update(
        n.name
        for n in nodes
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    expected = (
        symbols,
        (
            bound
            | {n for n, c in seen.items() if c > 1}
            | {n for n, c in counts.items() if c > 1}
        )
        & symbols.keys(),
    )
    calls = []

    def observe(node):
        calls.append(node)
        return original_walk(node)

    monkeypatch.setattr(ast, "walk", observe)
    assert contracts._db_python_symbols(tree) == expected
    assert calls == [tree]
    tree.body.append(
        ast.Assign(targets=[ast.Name(id="sa", ctx=ast.Store())], value=ast.Constant(1))
    )
    assert "sa" in contracts._db_python_symbols(tree)[1]
    assert calls == [tree, tree]


@pytest.mark.parametrize("cache_enabled", [False, True])
def test_negative_type_expectation_requires_strict_selected_checker(
    tmp_path, cache_enabled
):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pyright]\ninclude = ["test_negative.py"]\n'
        "reportUnnecessaryTypeIgnoreComment = true\n",
        encoding="utf-8",
    )
    (tmp_path / "test_negative.py").write_text(
        "def test_negative():\n    value: int = 'wrong'  # type: ignore\n"
        "def test_pass():\n    pass\n"
        "def test_constant():\n    assert True\n"
        'def test_docstring():\n    "Only a docstring"\n',
        encoding="utf-8",
    )
    for _ in range(2):
        findings = security_scan(tmp_path, cache_enabled=cache_enabled)["findings"]
        codes = {row["facts"].get("symbol"): row["code"] for row in findings}
        assert codes["test_negative"] == "QUALITY_TYPECHECK_NOT_VERIFIED"
        assert {
            codes[name] for name in ("test_pass", "test_constant", "test_docstring")
        } == {"QUALITY_HOLLOW_TEST"}


@pytest.mark.parametrize(
    "config",
    [
        'include = ["test_negative.py"]\nreportUnnecessaryTypeIgnoreComment = "warning"',
        'include = ["test_negative.py"]\nreportUnnecessaryTypeIgnoreComment = 1',
        'include = ["test_*.py"]\nreportUnnecessaryTypeIgnoreComment = true',
        'include = ["other.py"]\nreportUnnecessaryTypeIgnoreComment = true',
        'include = ["test_negative.py"]',
        'include = ["test_negative.py"]\nreportUnnecessaryTypeIgnoreComment = false',
        'include = ["test_negative.py"]\nreportUnnecessaryTypeIgnoreComment = "none"',
        'include = ["test_negative.py"]\nreportUnnecessaryTypeIgnoreComment = true\nenableTypeIgnoreComments = false',
        'include = ["test_negative.py"]\nreportUnnecessaryTypeIgnoreComment = true\nexclude = ["test_negative.py"]',
        'include = ["test_negative.py"]\nreportUnnecessaryTypeIgnoreComment = true\nignore = ["test_negative.py"]',
        'include = ["test_negative.py"]\nreportUnnecessaryTypeIgnoreComment = true\nextends = "other.json"',
    ],
)
def test_negative_type_expectation_does_not_credit_unproven_config(tmp_path, config):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pyright]\n" + config, encoding="utf-8"
    )
    (tmp_path / "test_negative.py").write_text(
        "def test_negative():\n    value: int = 'wrong'  # type: ignore\n",
        encoding="utf-8",
    )
    findings = security_scan(tmp_path, cache_enabled=False)["findings"]
    assert not any(row["code"] == "QUALITY_TYPECHECK_NOT_VERIFIED" for row in findings)
    assert any(row["code"] == "QUALITY_HOLLOW_TEST" for row in findings)


@pytest.mark.parametrize(
    "source",
    [
        'def test_negative():\n    value: str = "# type: ignore"\n',
        "def test_negative():\n    value: int = 1\n    # type: ignore\n",
        "def test_negative():\n    pass  # type: ignore\n",
        '# pyright: reportUnnecessaryTypeIgnoreComment=false\ndef test_negative():\n    value: int = "wrong"  # type: ignore\n',
    ],
)
def test_negative_type_expectation_requires_real_statement_comment(tmp_path, source):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pyright]\ninclude = ["test_negative.py"]\nreportUnnecessaryTypeIgnoreComment = true\n',
        encoding="utf-8",
    )
    (tmp_path / "test_negative.py").write_text(source, encoding="utf-8")
    findings = security_scan(tmp_path, cache_enabled=False)["findings"]
    assert not any(row["code"] == "QUALITY_TYPECHECK_NOT_VERIFIED" for row in findings)


@pytest.mark.parametrize("alternate", ["pyrightconfig.json", "basedpyrightconfig.json"])
def test_negative_type_expectation_rejects_alternate_config(tmp_path, alternate):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pyright]\ninclude = ["test_negative.py"]\nreportUnnecessaryTypeIgnoreComment = true\n',
        encoding="utf-8",
    )
    (tmp_path / "test_negative.py").write_text(
        "def test_negative():\n    value: int = 'wrong'  # type: ignore\n",
        encoding="utf-8",
    )
    first = security_scan(tmp_path)["finding_counts"]
    assert first.get("QUALITY_TYPECHECK_NOT_VERIFIED") == 1
    (tmp_path / alternate).write_text("{}", encoding="utf-8")
    assert security_scan(tmp_path)["finding_counts"].get("QUALITY_HOLLOW_TEST") == 1


def test_negative_type_expectation_config_and_source_changes_invalidate_cache(tmp_path):
    config = tmp_path / "pyproject.toml"
    source = tmp_path / "test_negative.py"
    config.write_text(
        '[tool.pyright]\ninclude = ["test_negative.py"]\nreportUnnecessaryTypeIgnoreComment = true\n',
        encoding="utf-8",
    )
    source.write_text(
        "def test_negative():\n    value: int = 'wrong'  # type: ignore\n",
        encoding="utf-8",
    )
    assert (
        security_scan(tmp_path)["finding_counts"].get("QUALITY_TYPECHECK_NOT_VERIFIED")
        == 1
    )
    config.write_text(
        '[tool.pyright]\ninclude = ["test_negative.py"]\nreportUnnecessaryTypeIgnoreComment = false\n',
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"].get("QUALITY_HOLLOW_TEST") == 1
    config.write_text(
        '[tool.pyright]\ninclude = ["test_negative.py"]\nreportUnnecessaryTypeIgnoreComment = true\n',
        encoding="utf-8",
    )
    source.write_text("def test_negative():\n    pass\n", encoding="utf-8")
    assert security_scan(tmp_path)["finding_counts"].get("QUALITY_HOLLOW_TEST") == 1


@pytest.mark.parametrize(
    "body,expected", [("pass", True), ("assert True", True), ("opaque()", False)]
)
def test_obvious_empty_body_contract_keeps_opaque_calls_unresolved(body, expected):
    from factoryline import type_intent_hollow as proof

    node = ast.parse("def test_behavior():\n    " + body + "\n").body[0]
    assert proof.obviously_empty_test_body(node) is expected


def test_provider_capture_and_sole_type_oracle_require_current_closed_source():
    from factoryline import type_intent_provider_provenance as provider

    source = "from typing import assert_type\ndef test_behavior():\n    assert_type(1, int)\n"
    proof, module, node, root, raw = _bound_unittest_test_node(source)
    relative = "tests/test_fixture.py"
    aliases = {"assert_type": "typing.assert_type"}
    assert provider.owner_module_effects_closed(module, node, "typing.assert_type")
    assert not provider.owner_module_effects_closed(
        module, node, "typing_extensions.assert_type"
    )
    assert proof.captured_provider_context_closed(
        module, relative, node, "typing.assert_type", None
    )
    assert proof.inert_type_assertion_only_oracle(
        node,
        aliases,
        module_aliases=aliases,
        scope_parameters=set(),
        provider_mutated=lambda *_: False,
        relative=relative,
        provider_context_closed=proof.captured_provider_context_closed,
    )
    module._security_source_context[1][root / relative] = raw + b"opaque()\n"
    assert not proof.captured_provider_context_closed(
        module, relative, node, "typing.assert_type", None
    )
    assert not proof.inert_type_assertion_only_oracle(
        node,
        aliases,
        module_aliases=aliases,
        scope_parameters=set(),
        provider_mutated=lambda *_: False,
        relative=relative,
        provider_context_closed=proof.captured_provider_context_closed,
    )


@pytest.mark.parametrize(
    "comment,declared,expected",
    [
        ("# type: ignore", True, True),
        ("# type: ignore", False, False),
        ("# unrelated", True, False),
    ],
)
def test_negative_checker_scope_is_exact_path_and_explicit_comment(
    comment, declared, expected
):
    from factoryline import type_intent_hollow as proof

    root = Path("C:/captured")
    selected = root / "tests/negative.py"
    other = root / "tests/other.py"
    contexts = {selected: {}, other: {"negative_typecheck": True}}
    proof.bind_negative_checker_context(
        root,
        contexts,
        {"negative_typecheck_selected": ["tests/negative.py"] if declared else []},
    )
    assert contexts[other]["negative_typecheck"] is False
    source = "def test_behavior():\n    value: str = 1 " + comment + "\n"
    module = ast.parse(source)
    module._oracle_source_lines = source.splitlines()
    node = module.body[0]
    node._oracle_module = module
    assert proof.negative_type_expectation(node, contexts[selected]) is expected
