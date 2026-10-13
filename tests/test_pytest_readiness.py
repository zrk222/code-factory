from pathlib import Path

from factoryline.pytest_readiness import collect_pytest_readiness
from factoryline.pytest_readiness import probe_assertion_propagation
from factoryline.pytest_readiness import probe_call_propagation
import pytest


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
        with pytest.raises(ValueError, match="inside the project"):
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
    frame = SimpleNamespace(
        f_lineno=2,
        f_code=SimpleNamespace(
            co_name="test_case", co_firstlineno=1, co_filename=str(source)
        ),
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
