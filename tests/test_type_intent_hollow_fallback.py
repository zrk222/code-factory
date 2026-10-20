import ast
from hashlib import sha256
from pathlib import Path

import pytest

from factoryline.review_audits import security_scan


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
