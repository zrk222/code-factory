from pathlib import Path

import factoryline.runtime_audit_process as runtime_audit_process
from factoryline.pytest_readiness import _typecheck_run
from factoryline.pytest_readiness import collect_pytest_readiness
from factoryline.pytest_readiness import probe_assertion_propagation
from factoryline.pytest_readiness import probe_call_propagation
from factoryline.pytest_readiness import probe_attribute_removal
from factoryline.pytest_readiness import probe_typecheck_transfer
from factoryline.pytest_readiness import _challenge_environment_digest
import pytest


def test_challenge_environment_requires_exact_supervisor_runtime_paths(tmp_path):
    home = str(tmp_path / "runtime-home")
    temp = str(tmp_path / "runtime-temp")
    mapping = {
        "HOME": home,
        "USERPROFILE": home,
        "TMP": temp,
        "TEMP": temp,
        "TMPDIR": temp,
    }

    assert _challenge_environment_digest(mapping, mapping)

    aliased = dict(mapping)
    aliased["HOME"] = str(tmp_path / "alias" / ".." / "runtime-home")
    with pytest.raises(ValueError, match="does not match"):
        _challenge_environment_digest(aliased, mapping)

    missing = dict(mapping)
    del missing["TMPDIR"]
    with pytest.raises(ValueError, match="does not match"):
        _challenge_environment_digest(missing, mapping)


def test_assertion_challenge_deselection_marks_selected_function_incomplete(
    tmp_path,
):
    from types import SimpleNamespace

    from factoryline.pytest_readiness import _AssertionChallenge

    challenge = _AssertionChallenge(
        tmp_path / "test_app.py",
        3,
        False,
        "test_value",
        1,
        kind="production_mutation",
        nodeid="test_app.py::test_value",
    )
    challenge.pytest_deselected(
        [SimpleNamespace(nodeid="test_app.py::test_value[param]")]
    )
    assert challenge.collection_incomplete is True


def test_typecheck_run_reports_the_requested_timeout(tmp_path, monkeypatch):
    observed = {}

    def run_bounded(*args):
        observed["timeout_seconds"] = args[2]
        return {"timeout_seconds": None, "exit_code": 0}

    monkeypatch.setattr(runtime_audit_process, "_launch", lambda *args: object())
    monkeypatch.setattr(runtime_audit_process, "_facts", lambda: {})
    monkeypatch.setattr(runtime_audit_process, "_run_child_bounded", run_bounded)
    facts = _typecheck_run(
        ["checker"],
        tmp_path,
        1.25,
        {},
        tmp_path / "stdout",
        tmp_path / "stderr",
    )
    assert observed["timeout_seconds"] == 2
    assert facts["timeout_seconds"] == 1.25


def _write_attribute_project(
    root, *, module_source="interface = object()\n", test_prefix=""
):
    (root / "product_module.py").write_text(module_source, encoding="utf-8")
    (root / "test_exports.py").write_text(
        test_prefix + "import product_module as product\n"
        "def test_exports():\n    product.interface\n",
        encoding="utf-8",
    )


def _write_typecheck_project(root, source, config="[mypy]\nstrict = True\n"):
    (root / "typecheck.ini").write_text(config, encoding="utf-8")
    test_source = root / "test_transfer.py"
    test_source.write_text(source, encoding="utf-8")
    signature_lines = [
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if "value:" in line
    ]
    signature_line = (
        signature_lines[0]
        if signature_lines
        else next(
            number
            for number, line in enumerate(source.splitlines(), start=1)
            if "def handler(" in line
        )
    )
    transfer_line = next(
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if "handler" in line and ("register(" in line or "handlers:" in line)
    )
    return signature_line, transfer_line


_CALLABLE_TRANSFER = (
    "from collections.abc import Callable\n"
    "class Target:\n    pass\n"
    "def register(callback: Callable[[Target], None]) -> None:\n    pass\n"
    "def test_transfer() -> None:\n"
    "    def handler(\n        value: Target,\n    ) -> None:\n        pass\n"
    "    register(handler)\n"
)


def test_typecheck_probe_observes_strict_callable_argument_transfer(tmp_path):
    signature, transfer = _write_typecheck_project(tmp_path, _CALLABLE_TRANSFER)

    result = probe_typecheck_transfer(
        tmp_path,
        "test_transfer.py::test_transfer",
        signature,
        transfer,
        "typecheck.ini",
    )

    assert result["schema"] == "factory.typecheck-transfer-probe.v1"
    assert result["status"] == "OBSERVED"
    assert result["baseline"]["diagnostics"] == []
    assert result["challenge"]["diagnostics"] == [
        {"path": "test_transfer.py", "line": transfer, "code": "arg-type"}
    ]
    assert result["checker_inputs_stable"] is True
    assert result["source_unchanged"] is True


def test_typecheck_probe_observes_dict_item_transfer(tmp_path):
    source = (
        "from collections.abc import Callable\n"
        "class Result:\n    pass\n"
        "def test_transfer() -> None:\n"
        "    def handler(\n        value: Result,\n    ) -> Result:\n"
        "        return Result()\n"
        '    handlers: dict[str, Callable[[Result], Result]] = {"x": handler}\n'
    )
    (tmp_path / "typecheck.ini").write_text("[mypy]\nstrict = True\n", encoding="utf-8")
    (tmp_path / "test_transfer.py").write_text(source, encoding="utf-8")

    result = probe_typecheck_transfer(
        tmp_path,
        "test_transfer.py::test_transfer",
        6,
        9,
        "typecheck.ini",
    )

    assert result["status"] == "OBSERVED"
    assert result["expected_diagnostic"] == "dict-item"
    assert result["challenge"]["diagnostics"] == [
        {"path": "test_transfer.py", "line": 9, "code": "dict-item"}
    ]


def test_typecheck_probe_widens_return_annotation_to_object(tmp_path):
    source = (
        "from collections.abc import Callable\n"
        "class Result:\n    pass\n"
        "def test_transfer() -> None:\n"
        "    def handler() -> Result:\n        return Result()\n"
        '    handlers: dict[str, Callable[[], Result]] = {"x": handler}\n'
    )
    (tmp_path / "typecheck.ini").write_text("[mypy]\nstrict = True\n", encoding="utf-8")
    (tmp_path / "test_transfer.py").write_text(source, encoding="utf-8")

    result = probe_typecheck_transfer(
        tmp_path,
        "test_transfer.py::test_transfer",
        5,
        7,
        "typecheck.ini",
    )

    assert result["status"] == "OBSERVED"
    assert result["mutation_type"] == "object"
    assert result["challenge"]["diagnostics"] == [
        {"path": "test_transfer.py", "line": 7, "code": "dict-item"}
    ]


def test_typecheck_signature_selectors_disambiguate_same_line(tmp_path):
    from factoryline.pytest_readiness import _typecheck_signature
    import ast

    tree = ast.parse(
        "def test_x():\n"
        "    def handler(request: Request, exc: Exception) -> Response: pass\n"
        "    consume(handler)\n"
    )
    callback = tree.body[0].body[0]
    with pytest.raises(ValueError):
        _typecheck_signature(callback, 2, None, None)
    parameter, kind, name = _typecheck_signature(callback, 2, "parameter", "exc")
    assert (kind, name, parameter.id) == ("parameter", "exc", "Exception")
    returned, kind, name = _typecheck_signature(callback, 2, "return", None)
    assert (kind, name, returned.id) == ("return", None, "Response")
    with pytest.raises(ValueError):
        _typecheck_signature(callback, 2, "parameter", "missing")
    with pytest.raises(ValueError):
        _typecheck_signature(callback, 2, "return", "exc")


def test_typecheck_signature_selectors_reject_ambiguous_parameters():
    import ast

    from factoryline.pytest_readiness import _typecheck_signature

    callback = (
        ast.parse("def test_x():\n    def handler(a: int, b: str): pass\n")
        .body[0]
        .body[0]
    )
    with pytest.raises(ValueError):
        _typecheck_signature(callback, 2, "parameter", None)
    selected, kind, name = _typecheck_signature(callback, 2, "parameter", "b")
    assert (kind, name, selected.id) == ("parameter", "b", "str")


def test_typecheck_scoped_ignores_reject_relevant_and_inventory_unrelated():
    import ast

    from factoryline.pytest_readiness import _typecheck_scoped_suppressions

    source = (
        "from typing import Any\n"
        "def test_selected():\n"
        "    consume(callback)\n"
        "def test_other():\n"
        "    value = 1  # type: ignore[assignment]\n"
    )
    tree = ast.parse(source)
    ignored = _typecheck_scoped_suppressions(source, tree, tree.body[1], "tests.py")
    assert ignored == [
        {
            "path": "tests.py",
            "line": 5,
            "reason": "unreferenced_test_body",
            "comment_sha256": __import__("hashlib")
            .sha256(b"# type: ignore[assignment]")
            .hexdigest(),
        }
    ]
    selected = source.replace(
        "    consume(callback)\n", "    value = 1  # type: ignore\n"
    )
    with pytest.raises(ValueError):
        _typecheck_scoped_suppressions(
            selected, ast.parse(selected), ast.parse(selected).body[1], "tests.py"
        )
    with pytest.raises(ValueError):
        _typecheck_scoped_suppressions(
            "# mypy: ignore-errors\n" + source,
            ast.parse("# mypy: ignore-errors\n" + source),
            ast.parse("# mypy: ignore-errors\n" + source).body[1],
            "tests.py",
        )


def test_typecheck_scoped_ignores_reject_module_and_import_ignores():
    import ast

    from factoryline.pytest_readiness import _typecheck_scoped_suppressions

    source = (
        "from typing import Any  # type: ignore\n"
        "def test_selected():\n    consume(callback)\n"
    )
    with pytest.raises(ValueError):
        _typecheck_scoped_suppressions(
            source, ast.parse(source), ast.parse(source).body[1], "tests.py"
        )


def test_typecheck_scoped_ignores_inventory_unreferenced_module_assignment():
    import ast

    from factoryline.pytest_readiness import _typecheck_scoped_suppressions

    source = (
        "from library import Api\n"
        "unrelated = Api(value=1)  # type: ignore[call-arg]\n"
        "def test_selected():\n"
        "    def callback(value: Api) -> None: pass\n"
        "    register(callback)\n"
    )
    tree = ast.parse(source)
    ignored = _typecheck_scoped_suppressions(source, tree, tree.body[2], "tests.py")
    assert ignored[0]["line"] == 2
    assert ignored[0]["reason"] == "unreferenced_assignment"
    dependent = source.replace("unrelated = Api", "Api = Api")
    parsed = ast.parse(dependent)
    with pytest.raises(ValueError):
        _typecheck_scoped_suppressions(dependent, parsed, parsed.body[2], "tests.py")


def test_typecheck_scoped_ignores_reject_reachable_test_and_definition_headers():
    import ast

    from factoryline.pytest_readiness import _typecheck_scoped_suppressions

    sources = (
        "def test_selected():\n    helper()\n"
        "def test_dependency():\n    value = 1  # type: ignore\n"
        "def helper():\n    test_dependency()\n",
        "def test_selected():\n    pass\ndef test_other(): pass  # type: ignore\n",
        "def test_selected():\n    pass\n"
        "@decorate  # type: ignore\ndef test_other():\n    pass\n",
    )
    for source in sources:
        tree = ast.parse(source)
        with pytest.raises(ValueError):
            _typecheck_scoped_suppressions(source, tree, tree.body[0], "tests.py")

    multiline = (
        "def test_selected():\n    pass\n"
        "def test_other(\n    value: int\n) -> None:\n"
        "    value = 1  # type: ignore[assignment]\n"
    )
    tree = ast.parse(multiline)
    ignored = _typecheck_scoped_suppressions(multiline, tree, tree.body[0], "tests.py")
    assert ignored[0]["reason"] == "unreferenced_test_body"


def test_typecheck_scoped_ignores_reject_transitively_referenced_test():
    import ast

    from factoryline.pytest_readiness import _typecheck_scoped_suppressions

    source = (
        "def test_selected():\n    helper()\n"
        "def test_dependency():\n    value = 1  # type: ignore\n"
        "def helper():\n    test_dependency()\n"
    )
    tree = ast.parse(source)
    with pytest.raises(ValueError):
        _typecheck_scoped_suppressions(source, tree, tree.body[0], "tests.py")


def test_typecheck_rejects_builtin_name_bindings(tmp_path):
    import ast

    from factoryline.pytest_readiness import _typecheck_builtin_shadowed

    sources = (
        "def f(int):\n    pass\n",
        "try:\n    pass\nexcept Exception as object:\n    pass\n",
        "match value:\n    case {'x': object}:\n        pass\n",
        "match value:\n    case [*int]:\n        pass\n",
    )
    assert all(_typecheck_builtin_shadowed(ast.parse(source)) for source in sources)


def test_typecheck_dependency_manifest_binds_py_typed_appearance(tmp_path):
    from factoryline.pytest_readiness import _typecheck_dependency_manifest

    package = tmp_path / "package"
    package.mkdir()
    source = package / "api.pyi"
    source.write_text("def call() -> None: ...\n", encoding="utf-8")
    before = _typecheck_dependency_manifest({source}, 1024 * 1024)
    (package / "py.typed").write_text("", encoding="utf-8")
    after = _typecheck_dependency_manifest({source}, 1024 * 1024)

    assert before != after


def test_typecheck_dependency_manifest_binds_namespace_directory(tmp_path):
    from factoryline.pytest_readiness import (
        _typecheck_dependency_manifest,
        _typecheck_import_names,
    )

    namespace = tmp_path / "backports"
    namespace.mkdir()
    (namespace / "api.pyi").write_text("value: int\n", encoding="utf-8")
    target = tmp_path / "test_namespace.py"
    target.write_text("import backports.api\n", encoding="utf-8")
    phase = {
        "modules": {namespace: "backports", target: "test_namespace"},
        "paths": {namespace, target},
    }
    names = _typecheck_import_names(phase, target)
    before = _typecheck_dependency_manifest(phase["paths"], 1024 * 1024)
    (namespace / "api.pyi").write_text("value: str\n", encoding="utf-8")
    after = _typecheck_dependency_manifest(phase["paths"], 1024 * 1024)

    assert "backports" in names
    assert before != after


def test_typecheck_dependency_ignores_are_limited_to_typed_function_locals(
    tmp_path,
):
    import ast

    from factoryline.pytest_readiness import (
        _typecheck_dependency_suppression_sites,
    )

    path = tmp_path / "site-packages" / "sample" / "module.py"
    path.parent.mkdir(parents=True)
    source = (
        "def helper(value: int) -> None:\n"
        "    local = None  # type: ignore[assignment]\n"
    )
    path.write_text(source, encoding="utf-8")
    rows = _typecheck_dependency_suppression_sites(
        source, ast.parse(source), path, "sample.module", source.encode()
    )
    assert rows[0]["path"] == "sample/module.py"
    assert rows[0]["module"] == "sample.module"
    assert rows[0]["line"] == 2
    for invalid in (
        "value = None  # type: ignore\n",
        "def helper(value) -> None:\n    local = None  # type: ignore\n",
        "def helper(value: int):\n    local = None  # type: ignore\n",
        "@decorator\ndef helper(value: int) -> None:\n    local = None  # type: ignore\n",
        "def helper(value: int) -> None:\n    a, b = 1, 2  # type: ignore\n",
        "def helper(value: int) -> None:\n    global local\n    local = None  # type: ignore\n",
        "def helper(value: int) -> None:\n    nonlocal_name = None\n    def nested() -> None:\n        nonlocal nonlocal_name\n        nonlocal_name = None  # type: ignore\n",
        "def helper(value: int) -> None:\n    class Nested:\n        def run(self) -> None:\n            local = None  # type: ignore\n",
    ):
        with pytest.raises(ValueError):
            _typecheck_dependency_suppression_sites(
                invalid, ast.parse(invalid), path, "sample.module", invalid.encode()
            )
    method = (
        "class Worker:\n"
        "    def run(self, value: int) -> None:\n"
        "        try:\n"
        "            pass\n"
        "        finally:\n"
        "            local = None  # type: ignore[assignment]\n"
    )
    method_sites = _typecheck_dependency_suppression_sites(
        method, ast.parse(method), path, "sample.Worker.run", method.encode()
    )
    assert len(method_sites) == 1
    async_method = (
        "class Worker:\n"
        "    async def run(self, value: int) -> None:\n"
        "        try:\n"
        "            pass\n"
        "        finally:\n"
        "            local = None  # type: ignore[assignment]\n"
    )
    async_sites = _typecheck_dependency_suppression_sites(
        async_method,
        ast.parse(async_method),
        path,
        "sample.Worker.run",
        async_method.encode(),
    )
    assert len(async_sites) == 1
    class_suite = "class Worker:\n    value = None  # type: ignore\n"
    with pytest.raises(ValueError):
        _typecheck_dependency_suppression_sites(
            class_suite,
            ast.parse(class_suite),
            path,
            "sample.Worker",
            class_suite.encode(),
        )
    method_global = (
        "class Worker:\n"
        "    def run(self, value: int) -> None:\n"
        "        global shared\n"
        "        shared = None  # type: ignore[assignment]\n"
    )
    with pytest.raises(ValueError):
        _typecheck_dependency_suppression_sites(
            method_global,
            ast.parse(method_global),
            path,
            "sample.Worker.run",
            method_global.encode(),
        )


def test_typecheck_resolver_manifest_binds_new_higher_priority_stubs(tmp_path):
    from factoryline.pytest_readiness import _typecheck_resolver_manifest

    roots = {
        "python_path": [str(tmp_path)],
        "mypy_path": [],
        "package_path": [],
        "typeshed_path": [],
    }
    before, _entries, _bytes = _typecheck_resolver_manifest(roots, {"sample.api"})
    stub_package = tmp_path / "sample-stubs"
    stub_package.mkdir()
    (stub_package / "__init__.pyi").write_text("", encoding="utf-8")
    after, _entries, _bytes = _typecheck_resolver_manifest(roots, {"sample.api"})

    assert before != after


def test_typecheck_resolver_inventory_stops_before_sorting_over_budget(
    tmp_path, monkeypatch
):
    import factoryline.pytest_readiness as readiness

    class Entry:
        def __init__(self, name):
            self.name = name

    class Entries:
        consumed = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            for index in range(100_000):
                self.consumed += 1
                yield Entry(str(index))

    scanned = Entries()
    monkeypatch.setattr(readiness.os, "scandir", lambda _path: scanned)
    rows = []
    with pytest.raises(ValueError, match="entry limit"):
        readiness._typecheck_inventory_tree(
            tmp_path, tmp_path.parent, rows, {"entries": 0, "bytes": 0, "limit": 1}, 0
        )
    assert scanned.consumed == 8192
    assert len(rows) == 1


def test_typecheck_rejects_source_suppression_directives():
    from factoryline.pytest_readiness import _typecheck_source_suppressed

    assert _typecheck_source_suppressed("x = 1  # type: ignore[arg-type]\n")
    assert _typecheck_source_suppressed("# mypy: disable-error-code=arg-type\n")
    assert not _typecheck_source_suppressed("# ordinary comment\nx = 1\n")


def test_typecheck_probe_fails_closed_for_ignored_transfer(tmp_path):
    source = _CALLABLE_TRANSFER.replace(
        "register(handler)", "register(handler)  # type: ignore[arg-type]"
    )
    signature, transfer = _write_typecheck_project(tmp_path, source)

    with pytest.raises(ValueError, match="Type ignore is inside selected test"):
        probe_typecheck_transfer(
            tmp_path,
            "test_transfer.py::test_transfer",
            signature,
            transfer,
            "typecheck.ini",
        )


def test_typecheck_probe_fails_closed_when_any_sink_accepts_mutation(tmp_path):
    source = _CALLABLE_TRANSFER.replace(
        "Callable[[Target], None]", "Callable[..., None]"
    )
    signature, transfer = _write_typecheck_project(tmp_path, source)

    result = probe_typecheck_transfer(
        tmp_path,
        "test_transfer.py::test_transfer",
        signature,
        transfer,
        "typecheck.ini",
    )

    assert result["status"] == "INCOMPLETE"
    assert result["baseline"]["diagnostics"] == []
    assert result["challenge"]["process"]["exit_code"] == 0
    assert result["challenge"]["diagnostics"] == []


def test_typecheck_config_rejects_plugins_and_module_suppressions(tmp_path):
    from factoryline.pytest_readiness import _typecheck_config_safe

    for config in (
        "[mypy]\nplugins = custom_plugin\n",
        "[mypy-test_transfer]\nignore_errors = True\n",
        "[tool.mypy]\n[[tool.mypy.overrides]]\nmodule = ['*']\n"
        "ignore_missing_imports = true\n",
    ):
        path = tmp_path / "mypy.ini"
        path.write_text(config, encoding="utf-8")
        with pytest.raises(ValueError):
            _typecheck_config_safe(path, path.read_bytes())

    path = tmp_path / "mypy.toml"
    false_config = "[tool.mypy]\nignore_errors = false\n"
    path.write_text(false_config, encoding="utf-8")
    _typecheck_config_safe(path, path.read_bytes())


def test_typecheck_probe_cli_requires_only_typecheck_arguments(monkeypatch, capsys):
    import json

    from factoryline import pytest_readiness

    result = {"schema": "factory.typecheck-transfer-probe.v1", "status": "OBSERVED"}
    seen = []

    def observe(*args, **kwargs):
        seen.append((args, kwargs))
        return result

    monkeypatch.setattr(pytest_readiness, "probe_typecheck_transfer", observe)
    assert (
        pytest_readiness.main(
            [
                "--root",
                ".",
                "--nodeid",
                "test_case.py::test_case",
                "--kind",
                "typecheck",
                "--checker-config",
                "mypy.ini",
                "--signature-line",
                "10",
                "--transfer-line",
                "18",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == result
    assert seen[0][0][2:] == (10, 18, "mypy.ini")


def test_typecheck_probe_cli_missing_inputs_is_structured(monkeypatch, capsys):
    import json

    from factoryline import pytest_readiness

    def unexpected(*args, **kwargs):
        raise AssertionError("probe must not run with missing typecheck inputs")

    monkeypatch.setattr(pytest_readiness, "probe_typecheck_transfer", unexpected)
    assert (
        pytest_readiness.main(
            [
                "--root",
                ".",
                "--nodeid",
                "test_case.py::test_case",
                "--kind",
                "typecheck",
            ]
        )
        == 2
    )
    response = json.loads(capsys.readouterr().out)
    assert response["schema"] == "factory.probe-validation.v1"
    assert response["status"] == "INVALID"
    assert response["kind"] == "typecheck"


@pytest.mark.parametrize(
    "invocation,expected",
    [
        ("check()", "OBSERVED"),
        ("pass", "INCOMPLETE"),
        (
            "try:\n        check()\n    except AssertionError:\n        pass",
            "INCOMPLETE",
        ),
    ],
)
def test_probe_assertion_propagation_callback_reachability(
    tmp_path, invocation, expected
):
    suite = tmp_path / "test_callback.py"
    suite.write_text(
        "def test_behavior():\n    def check():\n        assert compute() == 42\n    "
        + invocation
        + "\n\ndef compute():\n    return 42\n",
        encoding="utf-8",
    )
    result = probe_assertion_propagation(tmp_path, "test_callback.py::test_behavior", 3)
    assert result["status"] == expected
    assert result["source_unchanged"] is True
    assert str(tmp_path) not in __import__("json").dumps(result)


def test_probe_assertion_propagation_existing_failure_cannot_pass(tmp_path):
    (tmp_path / "test_case.py").write_text("def test_case():\n    assert 1 == 2\n")
    result = probe_assertion_propagation(tmp_path, "test_case.py::test_case", 2)
    assert result["status"] == "INCOMPLETE"
    assert result["challenge"] == {}


def test_probe_call_propagation_observes_bare_callback_invocation(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_case():\n    callback()\ndef callback():\n    pass\n",
        encoding="utf-8",
    )

    result = probe_call_propagation(tmp_path, "test_case.py::test_case", 2)

    assert result["schema"] == "factory.call-propagation-probe.v1"
    assert result["status"] == "OBSERVED"
    assert result["execution_point"].startswith("Before the selected call")
    assert result["production_function_mutation_sensitivity"] == "NOT_TESTED"
    assert result["challenge"]["schema"] == "factory.call-propagation-challenge.v1"
    assert result["challenge"]["reports"][1]["challenge_visible"] is True


def test_probe_attribute_removal_observes_native_missing_export(tmp_path):
    _write_attribute_project(tmp_path)
    module = tmp_path / "product_module.py"
    test_source = tmp_path / "test_exports.py"
    before = (module.read_bytes(), test_source.read_bytes())

    result = probe_attribute_removal(tmp_path, "test_exports.py::test_exports", 3)

    assert result["schema"] == "factory.attribute-removal-probe.v1"
    assert result["status"] == "OBSERVED"
    assert result["source_unchanged"] is True
    assert result["runtime_context_unchanged"] is True
    assert result["tool_unchanged"] is True
    assert result["baseline"]["collected"] == ["test_exports.py::test_exports"]
    assert result["baseline"]["attribute_module"]["state"] == "BASELINE_READY"
    assert result["challenge"]["attribute_module"]["state"] == "EXPORT_REMOVED"
    assert result["challenge"]["attribute_exception"] == {
        "type": "builtins.AttributeError",
        "name_matches": True,
        "object_identity_matches": True,
        "target_frame_matches": True,
        "matches": True,
    }
    assert (module.read_bytes(), test_source.read_bytes()) == before


def test_probe_attribute_removal_can_select_second_direct_module_read(tmp_path):
    (tmp_path / "product_module.py").write_text(
        "other = object()\ninterface = object()\n", encoding="utf-8"
    )
    (tmp_path / "test_exports.py").write_text(
        "import product_module as product\n"
        "def test_exports():\n"
        "    product.other\n"
        "    product.interface\n",
        encoding="utf-8",
    )

    result = probe_attribute_removal(tmp_path, "test_exports.py::test_exports", 4)

    assert result["status"] == "OBSERVED"
    assert result["export"] == "interface"
    assert result["challenge"]["reports"][1]["outcome"] == "failed"
    assert result["challenge"]["attribute_exception"]["matches"] is True


def test_probe_attribute_removal_keeps_earlier_missing_read_as_baseline_failure(
    tmp_path,
):
    (tmp_path / "product_module.py").write_text("interface = object()\n")
    (tmp_path / "test_exports.py").write_text(
        "import product_module as product\n"
        "def test_exports():\n"
        "    product.other\n"
        "    product.interface\n",
        encoding="utf-8",
    )

    result = probe_attribute_removal(tmp_path, "test_exports.py::test_exports", 4)

    assert result["status"] == "INCOMPLETE"
    assert result["baseline"]["reports"][1]["outcome"] == "failed"
    assert result["challenge"] == {}


@pytest.mark.parametrize(
    "source,line",
    [
        (
            "def test_case():\n    callback(\n    )\ndef callback():\n    pass\n",
            2,
        ),
        (
            "def test_case():\n    handler = callback\n    handler()\n"
            "def callback():\n    pass\n",
            3,
        ),
    ],
)
def test_probe_call_propagation_accepts_multiline_and_aliased_calls(
    tmp_path, source, line
):
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")

    result = probe_call_propagation(tmp_path, "test_case.py::test_case", line)

    assert result["status"] == "OBSERVED"
    assert result["challenge"]["schema"] == "factory.call-propagation-challenge.v1"


@pytest.mark.parametrize(
    "source,line,match",
    [
        (
            "from unittest.mock import Mock\nproduct = Mock()\n"
            "def test_exports():\n    product.missing\n",
            4,
            "stable module import binding",
        ),
        (
            "from unittest.mock import Mock\ndef product(): return Mock()\n"
            "def test_exports():\n    product().missing\n",
            4,
            "direct module attribute read",
        ),
        (
            "import product_module as product\n"
            "def test_exports():\n    try:\n        product.interface\n"
            "    except AttributeError:\n        pass\n",
            5,
            "requested line must contain one direct module attribute read",
        ),
        (
            "import product_module as product\n"
            "def test_exports():\n    return\n    product.interface\n",
            4,
            "test must contain only direct module attribute read statements",
        ),
        (
            "import pytest\nimport product_module as product\n"
            "@pytest.mark.skip\ndef test_exports():\n    product.interface\n",
            5,
            "test must contain only direct module attribute read statements",
        ),
    ],
)
def test_probe_attribute_removal_rejects_unsafe_or_never_run_shapes(
    tmp_path, source, line, match
):
    (tmp_path / "product_module.py").write_text("interface = object()\n")
    (tmp_path / "test_exports.py").write_text(source, encoding="utf-8")

    with pytest.raises(ValueError, match=match):
        probe_attribute_removal(tmp_path, "test_exports.py::test_exports", line)


def test_probe_attribute_removal_rejects_export_restored_before_call(tmp_path):
    _write_attribute_project(tmp_path)
    (tmp_path / "conftest.py").write_text(
        "def pytest_runtest_call(item):\n"
        "    if item.nodeid == 'test_exports.py::test_exports':\n"
        "        item.module.product.interface = object()\n",
        encoding="utf-8",
    )

    result = probe_attribute_removal(tmp_path, "test_exports.py::test_exports", 3)

    assert result["status"] == "INCOMPLETE"
    assert result["challenge"]["reports"][1]["outcome"] == "passed"
    assert result["challenge"]["attribute_exception"] == {}


def test_probe_attribute_removal_rejects_dynamic_module_getattr(tmp_path):
    _write_attribute_project(
        tmp_path, module_source="def __getattr__(name): return object()\n"
    )

    result = probe_attribute_removal(tmp_path, "test_exports.py::test_exports", 3)

    assert result["status"] == "INCOMPLETE"
    assert result["baseline"]["attribute_module"] == {
        "state": "REJECTED",
        "reason": "DYNAMIC_MODULE_GETATTR",
    }
    assert result["challenge"] == {}


def test_probe_attribute_removal_rejects_missing_baseline_export(tmp_path):
    _write_attribute_project(tmp_path, module_source="present = object()\n")

    result = probe_attribute_removal(tmp_path, "test_exports.py::test_exports", 3)

    assert result["status"] == "INCOMPLETE"
    assert result["baseline"]["reports"][1]["outcome"] == "failed"
    assert result["challenge"] == {}


def test_probe_attribute_removal_rejects_external_module_source(tmp_path):
    (tmp_path / "test_exports.py").write_text(
        "import pathlib as product\ndef test_exports():\n    product.Path\n",
        encoding="utf-8",
    )

    result = probe_attribute_removal(tmp_path, "test_exports.py::test_exports", 3)

    assert result["status"] == "INCOMPLETE"
    assert result["baseline"]["attribute_module"]["reason"] == "MODULE_SOURCE_NOT_LOCAL"
    assert result["challenge"] == {}


def test_probe_attribute_removal_detects_source_change(tmp_path):
    _write_attribute_project(
        tmp_path,
        module_source=(
            "from pathlib import Path\n"
            "Path('support.py').write_text('changed = True')\n"
            "interface = object()\n"
        ),
    )
    (tmp_path / "support.py").write_text("changed = False\n", encoding="utf-8")

    result = probe_attribute_removal(tmp_path, "test_exports.py::test_exports", 3)

    assert result["status"] == "INCOMPLETE"
    assert result["source_unchanged"] is False
    assert result["challenge"] == {}


def test_probe_attribute_removal_timeout_is_incomplete(tmp_path):
    _write_attribute_project(
        tmp_path,
        test_prefix="import time\ntime.sleep(2)\n",
    )

    result = probe_attribute_removal(
        tmp_path, "test_exports.py::test_exports", 5, timeout=0.2
    )

    assert result["status"] == "INCOMPLETE"
    assert result["baseline"] == {"status": "TIMEOUT"}
    assert result["challenge"] == {}


def test_attribute_probe_rejects_wrong_exception_name_or_module_identity(tmp_path):
    from factoryline.pytest_readiness import _attribute_exception_evidence

    module = __import__("types").ModuleType("product_module")
    wrong_name = AttributeError("missing")
    wrong_name.name = "other"
    wrong_name.obj = module
    wrong_object = AttributeError("missing")
    wrong_object.name = "interface"
    wrong_object.obj = __import__("types").ModuleType("other")

    name_evidence = _attribute_exception_evidence(
        wrong_name,
        None,
        tmp_path / "test_exports.py",
        3,
        "test_exports",
        1,
        module,
        "interface",
    )
    object_evidence = _attribute_exception_evidence(
        wrong_object,
        None,
        tmp_path / "test_exports.py",
        3,
        "test_exports",
        1,
        module,
        "interface",
    )

    assert name_evidence["name_matches"] is False
    assert name_evidence["matches"] is False
    assert object_evidence["object_identity_matches"] is False
    assert object_evidence["matches"] is False


def test_attribute_module_source_read_is_bounded(tmp_path):
    from factoryline.pytest_readiness import _attribute_source_bytes

    source = tmp_path / "large_module.py"
    source.write_bytes(b"x" * (4 * 1024 * 1024 + 2))

    resolved, content, error = _attribute_source_bytes(tmp_path, source, source)

    assert resolved is None
    assert content is None
    assert error == "MODULE_SOURCE_TOO_LARGE"


@pytest.mark.parametrize(
    "source,line",
    [
        ("def test_case():\n    result = callback()\n", 2),
        ("def test_case():\n    callback() or other()\n", 2),
        ("def test_case():\n    callback(); other()\n", 2),
        ("def test_case():\n    callback(other())\n", 2),
        ("def test_case():\n    if True: callback()\n", 2),
        ("callback()\ndef test_case():\n    pass\n", 1),
        ("async def test_case():\n    await callback()\n", 2),
        ("def test_case(value=callback()):\n    pass\n", 1),
        ("@register(callback())\ndef test_case():\n    pass\n", 1),
    ],
)
def test_probe_call_propagation_rejects_ambiguous_or_deferred_targets(
    tmp_path, source, line
):
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")

    with pytest.raises(ValueError, match="standalone call"):
        probe_call_propagation(tmp_path, "test_case.py::test_case", line)


@pytest.mark.parametrize(
    "source,line,changed",
    [
        (
            "def test_case():\n    def helper():\n        callback()\n"
            "def callback():\n    pass\n",
            3,
            False,
        ),
        (
            "def test_case():\n    try:\n        callback()\n"
            "    except AssertionError:\n        pass\n"
            "def callback():\n    pass\n",
            3,
            False,
        ),
        (
            "def test_case():\n    assert False\n    callback()\n"
            "def callback():\n    pass\n",
            3,
            False,
        ),
        (
            "from pathlib import Path\ndef test_case():\n"
            "    Path('created.py').write_text('changed = True')\n"
            "    callback()\ndef callback():\n    pass\n",
            4,
            True,
        ),
        (
            "import pytest\n@pytest.mark.xfail\ndef test_case():\n"
            "    callback()\ndef callback():\n    pass\n",
            4,
            False,
        ),
    ],
)
def test_probe_call_propagation_does_not_clear_incomplete_cases(
    tmp_path, source, line, changed
):
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")

    result = probe_call_propagation(tmp_path, "test_case.py::test_case", line)

    assert result["status"] == "INCOMPLETE"
    if "assert False" in source:
        assert result["challenge"] == {}
    if changed:
        assert result["source_unchanged"] is False


def _write_shadow_factoryline(path, marker):
    package = path / "factoryline"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "pytest_readiness.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('shadowed')\n"
        "def _challenge_worker(*args): raise RuntimeError('shadowed harness')\n",
        encoding="utf-8",
    )


def _write_assertion_project(root):
    (root / "workspace_support.py").write_text("VALUE = 42\n", encoding="utf-8")
    case = root / "test_case.py"
    case.write_text(
        "from workspace_support import VALUE\n"
        "def test_case():\n    assert VALUE == 42\n",
        encoding="utf-8",
    )
    return case


def test_assertion_probe_trusted_harness_precedes_workspace_shadow(tmp_path):
    marker = tmp_path / "workspace-shadow-loaded"
    _write_shadow_factoryline(tmp_path, marker)
    _write_assertion_project(tmp_path)

    result = probe_assertion_propagation(tmp_path, "test_case.py::test_case", 3)

    assert result["status"] == "OBSERVED"
    assert result["baseline"]["collected"] == ["test_case.py::test_case"]
    assert not marker.exists()


def test_assertion_probe_trusted_harness_precedes_inherited_pythonpath(
    tmp_path, monkeypatch
):
    inherited = tmp_path / "inherited"
    inherited.mkdir()
    marker = inherited / "inherited-shadow-loaded"
    _write_shadow_factoryline(inherited, marker)
    monkeypatch.setenv("PYTHONPATH", str(inherited))
    project = tmp_path / "project"
    project.mkdir()
    _write_assertion_project(project)

    result = probe_assertion_propagation(project, "test_case.py::test_case", 3)

    assert result["status"] == "OBSERVED"
    assert result["baseline"]["collected"] == ["test_case.py::test_case"]
    assert not marker.exists()


def test_probe_assertion_propagation_rejects_non_assertion_and_escape(tmp_path):
    (tmp_path / "test_case.py").write_text("def test_case():\n    pass\n")
    with pytest.raises(ValueError, match="Python assert"):
        probe_assertion_propagation(tmp_path, "test_case.py::test_case", 2)
    with pytest.raises(ValueError, match="inside the project"):
        probe_assertion_propagation(tmp_path, "../outside.py::test_case", 2)


@pytest.mark.parametrize("marker", ["@pytest.mark.skip", "@pytest.mark.xfail"])
def test_probe_assertion_propagation_skip_and_xfail_are_incomplete(tmp_path, marker):
    (tmp_path / "test_case.py").write_text(
        "import pytest\n" + marker + "\ndef test_case():\n    assert True\n"
    )
    assert (
        probe_assertion_propagation(tmp_path, "test_case.py::test_case", 4)["status"]
        == "INCOMPLETE"
    )


def test_probe_assertion_propagation_timeout_is_incomplete(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_case():\n    import time\n    time.sleep(30)\n    assert True\n"
    )
    result = probe_assertion_propagation(
        tmp_path, "test_case.py::test_case", 4, timeout=0.1
    )
    assert result["status"] == "INCOMPLETE"
    assert result["baseline"] == {"status": "TIMEOUT"}


def test_probe_assertion_propagation_rejects_forged_marker_failure(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_case():\n    try:\n        assert compute() == 42\n"
        "    except AssertionError:\n"
        "        raise ValueError('CF_ASSERTION_PROPAGATION_CHALLENGE')\n"
        "def compute():\n    return 42\n"
    )
    result = probe_assertion_propagation(tmp_path, "test_case.py::test_case", 3)
    assert result["status"] == "INCOMPLETE"
    assert result["challenge"]["reports"][1]["challenge_visible"] is False


def test_probe_assertion_propagation_async_thread_parameter(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "import asyncio\nimport pytest\nfrom concurrent.futures import ThreadPoolExecutor\n"
        "@pytest.mark.parametrize('value', [42, 43])\n"
        "def test_case(value):\n    def check():\n        assert value == 42\n"
        "    async def run():\n        with ThreadPoolExecutor() as pool:\n"
        "            pool.submit(check).result()\n    asyncio.run(run())\n"
    )
    result = probe_assertion_propagation(tmp_path, "test_case.py::test_case[42]", 7)
    assert result["status"] == "OBSERVED"
    assert result["baseline"]["collected"] == ["test_case.py::test_case[42]"]


def test_probe_assertion_propagation_detects_source_drift(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from pathlib import Path\ndef test_case():\n"
        "    Path('created.py').write_text('changed = True')\n"
        "    assert compute() == 42\ndef compute():\n    return 42\n"
    )
    result = probe_assertion_propagation(tmp_path, "test_case.py::test_case", 4)
    assert result["status"] == "INCOMPLETE"
    assert result["source_unchanged"] is False


@pytest.mark.parametrize("status,code", [("OBSERVED", 0), ("INCOMPLETE", 2)])
def test_assertion_probe_main_reports_only_actual_observation(
    monkeypatch, capsys, status, code
):
    from factoryline import pytest_readiness

    monkeypatch.setattr(
        pytest_readiness,
        "probe_assertion_propagation",
        lambda *a, **k: {"status": status, "semantic_strength": "NOT_ASSESSED"},
    )
    assert (
        pytest_readiness.main(
            ["--root", ".", "--nodeid", "test_case.py::test_case", "--line", "2"]
        )
        == code
    )
    assert __import__("json").loads(capsys.readouterr().out)["status"] == status


def test_call_probe_cli_selects_distinct_kind_and_schema(monkeypatch, capsys):
    from factoryline import pytest_readiness

    result = {"schema": "factory.call-propagation-probe.v1", "status": "OBSERVED"}
    monkeypatch.setattr(
        pytest_readiness, "probe_call_propagation", lambda *a, **k: result
    )

    assert (
        pytest_readiness.main(
            [
                "--root",
                ".",
                "--nodeid",
                "test_case.py::test_case",
                "--line",
                "2",
                "--kind",
                "call",
            ]
        )
        == 0
    )
    assert __import__("json").loads(capsys.readouterr().out) == result


def test_attribute_probe_cli_validation_is_structured_and_sanitized(
    monkeypatch, capsys
):
    import json
    from factoryline import pytest_readiness

    def reject(*args, **kwargs):
        raise ValueError("private /host/absolute/path")

    monkeypatch.setattr(pytest_readiness, "probe_attribute_removal", reject)
    assert (
        pytest_readiness.main(
            [
                "--root",
                ".",
                "--nodeid",
                "test_case.py::test_case",
                "--line",
                "2",
                "--kind",
                "attribute",
            ]
        )
        == 2
    )
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["status"] == "INVALID"
    assert result["schema"] == "factory.probe-validation.v1"
    assert "/host/absolute/path" not in output


def test_typecheck_resolves_explicit_top_level_callback_transfer(tmp_path):
    source = (
        "from collections.abc import Callable\n"
        "class Target: ...\n"
        "def handler(value: Target) -> None: pass\n"
        "def register(callback: Callable[[Target], None]) -> None: pass\n"
        "def test_transfer() -> None:\n"
        "    register(handler)\n"
    )
    signature, transfer = _write_typecheck_project(tmp_path, source)
    result = probe_typecheck_transfer(
        tmp_path,
        "test_transfer.py::test_transfer",
        signature,
        transfer,
        "typecheck.ini",
        signature_kind="parameter",
        parameter_name="value",
    )

    assert result["status"] == "OBSERVED"
    assert result["challenge"]["diagnostics"] == [
        {"path": "test_transfer.py", "line": transfer, "code": "arg-type"}
    ]


def test_attribute_probe_cli_selects_distinct_kind_and_schema(monkeypatch, capsys):
    from factoryline import pytest_readiness

    result = {
        "schema": "factory.attribute-removal-probe.v1",
        "status": "OBSERVED",
    }
    monkeypatch.setattr(
        pytest_readiness, "probe_attribute_removal", lambda *a, **k: result
    )

    assert (
        pytest_readiness.main(
            [
                "--root",
                ".",
                "--nodeid",
                "test_case.py::test_case",
                "--line",
                "2",
                "--kind",
                "attribute",
            ]
        )
        == 0
    )
    assert __import__("json").loads(capsys.readouterr().out) == result


def test_attribute_probe_cli_runs_baseline_and_native_mutation(tmp_path, capsys):
    from factoryline import pytest_readiness

    _write_attribute_project(tmp_path)

    code = pytest_readiness.main(
        [
            "--root",
            str(tmp_path),
            "--nodeid",
            "test_exports.py::test_exports",
            "--line",
            "3",
            "--kind",
            "attribute",
        ]
    )

    result = __import__("json").loads(capsys.readouterr().out)
    assert code == 0
    assert result["schema"] == "factory.attribute-removal-probe.v1"
    assert result["status"] == "OBSERVED"
    assert result["baseline"]["reports"][1]["outcome"] == "passed"
    assert result["challenge"]["attribute_exception"]["matches"] is True


def test_assertion_probe_input_and_binding_limits(tmp_path, monkeypatch):
    from factoryline.pytest_readiness import (
        _challenge_inputs,
        _challenge_source_binding,
    )

    suite = tmp_path / "test_case.py"
    suite.write_text("def test_case():\n    assert True; assert True\n")
    with pytest.raises(ValueError, match="exactly one"):
        _challenge_inputs(tmp_path, "test_case.py::test_case", 2)
    with pytest.raises(ValueError, match="timeout"):
        probe_assertion_propagation(
            tmp_path, "test_case.py::test_case", 2, timeout=True
        )
    suite.write_text("def test_case():\n    assert True\n")
    original = Path.is_symlink
    with monkeypatch.context() as patch:
        patch.setattr(Path, "is_symlink", lambda p: p == tmp_path or original(p))
        with pytest.raises(ValueError, match="linked path"):
            _challenge_inputs(tmp_path, "test_case.py::test_case", 2)
    with suite.open("wb") as stream:
        stream.truncate(4 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="4 MiB"):
        _challenge_inputs(tmp_path, "test_case.py::test_case", 2)
    with suite.open("wb") as stream:
        stream.truncate(128 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="128 MiB"):
        _challenge_source_binding(tmp_path)
    suite.unlink()


def test_challenge_source_binding_preserves_existing_digest_format(
    tmp_path, monkeypatch
):
    import hashlib
    import json

    from factoryline import review_audits
    from factoryline.pytest_readiness import _challenge_source_binding

    source = tmp_path / "test_case.py"
    content = b"def test_case():\n    assert True\n"
    source.write_bytes(content)
    monkeypatch.setattr(review_audits, "_security_source_files", lambda root: [source])
    expected = hashlib.sha256(
        json.dumps(
            [["test_case.py", hashlib.sha256(content).hexdigest()]],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    assert _challenge_source_binding(tmp_path) == expected


def test_challenge_source_digest_bounds_growth_after_size_check(tmp_path, monkeypatch):
    from factoryline.pytest_readiness import _challenge_source_digest

    class GrowingStream:
        def __init__(self):
            self.requests = []

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            self.requests.append(size)
            return b"x" * size

    path = tmp_path / "growing.py"
    stream = GrowingStream()
    original_open = Path.open

    def open_growing_stream(candidate, mode="r", *args, **kwargs):
        if candidate == path:
            assert mode == "rb"
            return stream
        return original_open(candidate, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_growing_stream)
    with pytest.raises(ValueError, match="128 MiB"):
        _challenge_source_digest(path, 5)
    assert stream.requests == [6]


def test_assertion_probe_requires_exact_terminal_reports():
    from factoryline.pytest_readiness import _exact_challenge_outcome

    node = "test_case.py::test_case"
    reports = [
        {"nodeid": node, "phase": phase, "outcome": "passed", "xfail": False}
        for phase in ("setup", "call", "teardown")
    ]
    observation = {"collected": [node], "hits": 1, "reports": reports, "exit_code": 0}
    assert _exact_challenge_outcome(observation, node, "passed")
    assert not _exact_challenge_outcome({**observation, "exit_code": 2}, node, "passed")
    assert not _exact_challenge_outcome(
        {**observation, "reports": reports[:-1]}, node, "passed"
    )


def test_assertion_probe_matches_python310_code_identity(tmp_path):
    from types import SimpleNamespace
    from factoryline.pytest_readiness import _AssertionChallenge

    source = tmp_path / "test_case.py"
    source.write_text("def test_case():\n    assert True\n")
    plugin = _AssertionChallenge(source.resolve(), 2, False, "test_case", 1)
    plugin.active = True
    plugin.phase = "call"
    frame = SimpleNamespace(
        f_lineno=2,
        f_code=SimpleNamespace(
            co_name="test_case", co_firstlineno=1, co_filename=str(source)
        ),
        f_globals={"__name__": "test_case"},
    )
    plugin.trace(frame, "line", None)
    assert plugin.hits == 1
    frame.f_code.co_firstlineno = 10
    plugin.trace(frame, "line", None)
    assert plugin.hits == 1


def test_assertion_probe_matches_decorated_nested_function(tmp_path):
    from factoryline.pytest_readiness import probe_assertion_propagation

    (tmp_path / "test_case.py").write_text(
        "def identity(fn):\n    return fn\ndef test_case():\n"
        "    @identity\n    def check():\n        assert True\n    check()\n"
    )
    result = probe_assertion_propagation(tmp_path, "test_case.py::test_case", 6)
    assert result["status"] == "OBSERVED"
    assert result["semantic_strength"] == "NOT_ASSESSED"


@pytest.mark.parametrize("layout", ["flat", "src", "namespace"])
def test_assertion_probe_binds_imported_project_module_origin(tmp_path, layout):
    from factoryline.pytest_readiness import probe_assertion_propagation

    package_name = "ns" if layout == "namespace" else "pkg"
    package = tmp_path / ("src" if layout != "flat" else "") / package_name
    package.mkdir(parents=True)
    if layout != "namespace":
        (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "production.py").write_text(
        "def value():\n    return True\n", encoding="utf-8"
    )
    prefix = (
        "import sys\nfrom pathlib import Path\n"
        "sys.path.insert(0, str(Path(__file__).parent / 'src'))\n"
        if layout != "flat"
        else ""
    )
    test_source = prefix + (
        f"from {package_name}.production import value\n"
        "def test_case():\n    assert value() is True\n"
    )
    (tmp_path / "test_case.py").write_text(test_source, encoding="utf-8")
    result = probe_assertion_propagation(
        tmp_path, "test_case.py::test_case", len(test_source.splitlines())
    )

    assert result["status"] == "OBSERVED", (
        result["baseline"].get("origin_status"),
        result["baseline"].get("executed_modules"),
        result["baseline"].get("reports"),
        result["baseline"].get("hits"),
    )
    assert result["source_manifest_status"] == "BOUND"
    assert result["module_origin_status"] == "BOUND"
    for observation in (result["baseline"], result["challenge"]):
        production = next(
            row
            for row in observation["executed_modules"]
            if row["module_name"] == f"{package_name}.production"
        )
        assert production["nodeid"] == "test_case.py::test_case"
        assert production["phase"] == "collection"
        assert production["observation_kind"] == "imported_module"
        assert (
            production["path"]
            == ("src/" if layout != "flat" else "") + package_name + "/production.py"
        )
        assert production["status"] == "BOUND"
        assert all(
            row["module_name"] not in {"pathlib", "factoryline.pytest_readiness"}
            for row in observation["executed_modules"]
        )
    assert any(
        row["module_name"] == f"{package_name}.production"
        and row["phase"] == "call"
        and row["observation_kind"] == "executed_frame"
        for row in result["baseline"]["executed_modules"]
    )
    assert not any(
        row["module_name"] == f"{package_name}.production"
        and row["phase"] == "call"
        and row["observation_kind"] == "executed_frame"
        for row in result["challenge"]["executed_modules"]
    )


def test_assertion_probe_rejects_preloaded_external_project_module(tmp_path):
    from factoryline.pytest_readiness import probe_assertion_propagation

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "production.py").write_text(
        "def value():\n    return True\n", encoding="utf-8"
    )
    (tmp_path / "production.py").write_text(
        "def value():\n    return True\n", encoding="utf-8"
    )
    (tmp_path / "conftest.py").write_text(
        f"import sys\nsys.path.insert(0, {str(outside)!r})\nimport production\n",
        encoding="utf-8",
    )
    test_source = (
        "import production\ndef test_case():\n    assert production.value() is True\n"
    )
    (tmp_path / "test_case.py").write_text(test_source, encoding="utf-8")
    result = probe_assertion_propagation(
        tmp_path, "test_case.py::test_case", len(test_source.splitlines())
    )

    assert result["status"] == "INCOMPLETE"
    assert result["source_manifest_status"] == "BOUND"
    assert result["module_origin_status"] == "INCOMPLETE"
    assert any(
        row["module_name"] == "production" and row["status"] == "MISMATCH"
        for row in result["baseline"].get("executed_modules", [])
    )
    external = next(
        row
        for row in result["baseline"]["executed_modules"]
        if row["module_name"] == "production"
    )
    assert external["origin"] == "external"
    assert len(external["origin_sha256"]) == 64
    assert str(outside) not in repr(result)


def test_challenge_origin_row_cap_fails_closed(tmp_path):
    from factoryline.pytest_readiness import _AssertionChallenge

    plugin = _AssertionChallenge(tmp_path / "test_case.py", 1, False, "test", 1)
    for index in range(513):
        plugin._add_origin(
            {
                "nodeid": "test_case.py::test_case",
                "phase": "call",
                "module_name": f"module_{index}",
                "status": "BOUND",
            }
        )

    assert len(plugin.origins) == 512
    assert plugin.origin_status == "INCOMPLETE"
    assert plugin.origin_limit_exceeded is True


def test_call_probe_binds_project_module_origin(tmp_path):
    from factoryline.pytest_readiness import probe_call_propagation

    package = tmp_path / "src" / "pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "production.py").write_text(
        "def execute():\n    return None\n", encoding="utf-8"
    )
    test_source = (
        "import sys\nfrom pathlib import Path\n"
        "sys.path.insert(0, str(Path(__file__).parent / 'src'))\n"
        "from pkg.production import execute\n"
        "def test_case():\n    execute()\n"
    )
    (tmp_path / "test_case.py").write_text(test_source, encoding="utf-8")
    result = probe_call_propagation(
        tmp_path, "test_case.py::test_case", len(test_source.splitlines())
    )

    assert result["status"] == "OBSERVED"
    assert result["module_origin_status"] == "BOUND"
    assert any(
        row["module_name"] == "pkg.production"
        and row["path"] == "src/pkg/production.py"
        and row["phase"] == "call"
        and row["observation_kind"] == "executed_frame"
        and row["status"] == "BOUND"
        for row in result["baseline"]["executed_modules"]
    )
    assert not any(
        row["module_name"] == "pkg.production"
        and row["phase"] == "call"
        and row["observation_kind"] == "executed_frame"
        for row in result["challenge"]["executed_modules"]
    )


def test_challenge_binds_aliased_editable_loader_from_inventory(tmp_path):
    import hashlib
    import importlib.machinery
    import importlib.util

    from factoryline.pytest_readiness import _challenge_module_origin

    source = tmp_path / "src" / "pkg" / "production.py"
    source.parent.mkdir(parents=True)
    source.write_text("value = 42\n", encoding="utf-8")
    name = "editable_alias.production"
    loader = importlib.machinery.SourceFileLoader(name, str(source))
    spec = importlib.util.spec_from_loader(name, loader, origin=str(source))
    module = importlib.util.module_from_spec(spec)
    row = _challenge_module_origin(
        name,
        module,
        tmp_path,
        {"src/pkg/production.py": hashlib.sha256(source.read_bytes()).hexdigest()},
        "test_case.py::test_case",
        "collection",
    )

    assert row["status"] == "BOUND"
    assert row["path"] == "src/pkg/production.py"
    assert row["origin"] == "src/pkg/production.py"
    assert row["loader"] == "SourceFileLoader"


def test_challenge_origin_validation_rejects_missing_and_changed_sources(tmp_path):
    import hashlib
    import json

    from factoryline.pytest_readiness import _challenge_origins_bound

    source = tmp_path / "test_case.py"
    source.write_text("def test_case():\n    assert True\n", encoding="utf-8")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    manifest = {"test_case.py": digest}
    manifest_hash = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    observation = {
        "origin_status": "BOUND",
        "origin_limit_exceeded": False,
        "executed_source_manifest_sha256": manifest_hash,
        "executed_modules": [
            {
                "nodeid": "test_case.py::test_case",
                "phase": "collection",
                "module_name": "test_case",
                "observation_kind": "imported_module",
                "origin": "test_case.py",
                "path": "test_case.py",
                "source_sha256": digest,
                "status": "BOUND",
            },
            {
                "nodeid": "test_case.py::test_case",
                "phase": "call",
                "module_name": "test_case",
                "observation_kind": "executed_frame",
                "origin": "test_case.py",
                "path": "test_case.py",
                "source_sha256": digest,
                "status": "BOUND",
            },
        ],
    }
    assert _challenge_origins_bound(
        observation, tmp_path, manifest, "test_case.py::test_case", source
    )
    assert not _challenge_origins_bound(
        {**observation, "executed_modules": []},
        tmp_path,
        manifest,
        "test_case.py::test_case",
        source,
    )
    source.write_text("changed\n", encoding="utf-8")
    assert not _challenge_origins_bound(
        observation, tmp_path, manifest, "test_case.py::test_case", source
    )


@pytest.mark.parametrize(
    "body",
    ["return; assert True", "value = 42; assert value == 42", "if False: assert True"],
)
def test_assertion_probe_rejects_shared_statement_line(tmp_path, body):
    from factoryline.pytest_readiness import probe_assertion_propagation

    (tmp_path / "test_case.py").write_text("def test_case():\n    " + body + "\n")
    with pytest.raises(ValueError, match="exactly one Python assert"):
        probe_assertion_propagation(tmp_path, "test_case.py::test_case", 2)


@pytest.mark.parametrize("reports", [None, [None], [{}], "invalid"])
def test_assertion_probe_malformed_challenge_is_incomplete(
    tmp_path, monkeypatch, reports
):
    import factoryline.pytest_readiness as readiness

    (tmp_path / "test_case.py").write_text("def test_case():\n    assert True\n")
    node = "test_case.py::test_case"
    baseline = {
        "collected": [node],
        "hits": 1,
        "exit_code": 0,
        "reports": [
            {"nodeid": node, "phase": phase, "outcome": "passed", "xfail": False}
            for phase in ("setup", "call", "teardown")
        ],
    }
    observations = iter(
        [baseline, {"collected": [node], "hits": 1, "exit_code": 1, "reports": reports}]
    )
    monkeypatch.setattr(
        readiness, "_run_assertion_challenge", lambda *args: next(observations)
    )
    result = readiness.probe_assertion_propagation(tmp_path, node, 2)
    assert result["status"] == "INCOMPLETE"
    assert result["observer_integrity"] == "IN_PROCESS_NOT_ATTESTED"


@pytest.mark.parametrize("payload", ["not json", "[]", "null"])
def test_assertion_probe_rejects_malformed_observation_file(tmp_path, payload):
    from factoryline.pytest_readiness import _probe_observation

    output = tmp_path / "observation.json"
    output.write_text(payload)
    assert _probe_observation(output, {"exit_code": 0})["status"] == "RUNNER_ERROR"
    output.unlink()
    assert _probe_observation(output, {"exit_code": 0})["status"] == "RUNNER_ERROR"


def test_probe_observation_accepts_valid_bounded_json_report(tmp_path):
    from factoryline.pytest_readiness import _probe_observation

    output = tmp_path / "observation.json"
    output.write_text('{"status":"OBSERVED"}', encoding="utf-8")

    assert _probe_observation(output, {"exit_code": 0}) == {
        "status": "OBSERVED",
        "process": {"exit_code": 0},
    }


def test_probe_observation_rejects_invalid_utf8_and_oversized_report(tmp_path):
    from factoryline.pytest_readiness import _probe_observation

    output = tmp_path / "observation.json"
    output.write_bytes(b"{\xff}")
    assert _probe_observation(output, {"exit_code": 0})["status"] == "RUNNER_ERROR"

    output.write_bytes(b" " * (1024 * 1024 + 10))
    result = _probe_observation(output, {"exit_code": 0})
    assert result["status"] == "RUNNER_LIMIT"
    assert result["report_limit_exceeded"] is True
    assert result["report_limit_bytes"] == 1024 * 1024


def test_assertion_probe_aborts_collection_of_multiple_cases(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from pathlib import Path\nclass TestCases:\n"
        "    def test_one(self):\n        assert True\n"
        "    def test_two(self):\n        Path('executed').touch()\n"
    )
    result = probe_assertion_propagation(tmp_path, "test_case.py::TestCases", 4)
    assert result["status"] == "INCOMPLETE"
    assert result["baseline"]["exit_code"] == 4
    assert not (tmp_path / "executed").exists()


def test_mutation_collector_marks_empty_selection_incomplete_without_indexing(tmp_path):
    from types import SimpleNamespace

    from factoryline.pytest_readiness import _AssertionChallenge

    plugin = _AssertionChallenge(
        tmp_path / "test_case.py",
        1,
        False,
        "test_case",
        1,
        root=tmp_path,
        source_manifest={},
        allow_multiple=True,
    )
    with pytest.raises(pytest.UsageError, match="collected no cases"):
        plugin.pytest_collection_finish(SimpleNamespace(items=[]))

    assert plugin.collection_incomplete is True
    assert plugin.collected == []
    assert plugin.origins == []


def test_assertion_probe_bounds_runner_output(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "import sys\ndef test_case():\n    sys.stdout.write('x' * (9 * 1024 * 1024))\n"
        "    assert compute() == 42\ndef compute():\n    return 42\n"
    )
    result = probe_assertion_propagation(tmp_path, "test_case.py::test_case", 4)
    assert result["status"] == "INCOMPLETE"
    assert result["challenge"]["status"] == "RUNNER_LIMIT"
    assert result["challenge"]["process"]["output_limit_exceeded"] is True


def test_setup_phase_skip_cannot_satisfy_readiness(tmp_path: Path) -> None:
    suite = tmp_path / "test_sabotage.py"
    suite.write_text(
        "import pytest\n"
        "def test_pass(): assert True\n"
        "@pytest.mark.skip(reason='sabotage')\n"
        "def test_setup_skip(): assert True\n",
        encoding="utf-8",
    )
    result = collect_pytest_readiness([str(suite)])
    assert result == {"exit_code": 0, "passed": 1, "skipped": 1, "xfailed": 0}
    assert (result["passed"], result["skipped"], result["xfailed"]) != (1, 0, 0)


def test_collection_skip_cannot_satisfy_readiness(tmp_path: Path) -> None:
    suite = tmp_path / "test_collection_sabotage.py"
    suite.write_text(
        "import pytest\n"
        "pytest.skip('collection sabotage', allow_module_level=True)\n"
        "def test_never_collected(): assert True\n",
        encoding="utf-8",
    )
    result = collect_pytest_readiness([str(suite)])
    assert result == {"exit_code": 5, "passed": 0, "skipped": 1, "xfailed": 0}
