"""Exact pytest outcome collection for release-readiness smoke gates."""

from __future__ import annotations

import os
import ast
import hashlib
import json
import sys
import tempfile
import threading
import time

import pytest
from pathlib import Path


class _AssertionChallenge:
    """Observe one assertion during the selected call phase, including new threads."""

    def __init__(self, path, line, inject, qualname, firstlineno, kind="assertion"):
        self.path, self.line, self.inject = path, line, inject
        self.qualname = qualname
        self.firstlineno = firstlineno
        self.kind = kind
        self.active = False
        self.hits = 0
        self.reports = []
        self.collected = []
        label = "CALL" if kind == "call" else "ASSERTION"
        self.error = AssertionError(f"CF_{label}_PROPAGATION_CHALLENGE")
        self.escaped = set()

    def trace(self, frame, event, arg):
        """Raise at the reviewed assertion during the selected call phase."""
        if self.active and event == "line" and frame.f_lineno == self.line:
            if (
                frame.f_code.co_name == self.qualname.rsplit(".", 1)[-1]
                and frame.f_code.co_firstlineno == self.firstlineno
                and Path(frame.f_code.co_filename).resolve() == self.path
            ):
                self.hits += 1
                if self.inject:
                    raise self.error
        return self.trace

    def pytest_collection_finish(self, session):
        """Reject ambiguous collection before any selected test can execute."""
        self.collected = [item.nodeid for item in session.items]
        if len(session.items) != 1:
            raise pytest.UsageError(
                "Propagation probes require exactly one collected case"
            )

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_call(self, item):
        """Trace only the selected call phase and restore existing observers."""
        old, old_thread = sys.gettrace(), threading.gettrace()
        self.active = True
        sys.settrace(self.trace)
        threading.settrace(self.trace)
        try:
            yield
        finally:
            self.active = False
            sys.settrace(old)
            threading.settrace(old_thread)

    def pytest_runtest_logreport(self, report):
        """Record exact terminal phase outcomes without retaining raw output."""
        self.reports.append(
            {
                "nodeid": report.nodeid,
                "phase": report.when,
                "outcome": report.outcome,
                "xfail": hasattr(report, "wasxfail"),
                "challenge_visible": (report.nodeid, report.when) in self.escaped,
            }
        )

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        """Identify the injected exception by identity rather than its text."""
        if call.excinfo is not None and _probe_exception_contains(
            call.excinfo.value, self.error
        ):
            self.escaped.add((item.nodeid, call.when))
        yield


def _probe_exception_contains(error, expected, depth=0):
    if error is expected:
        return True
    if depth >= 8:
        return False
    return any(
        _probe_exception_contains(child, expected, depth + 1)
        for child in getattr(error, "exceptions", ())
    )


def _challenge_worker(config, output):
    plugin = _AssertionChallenge(
        Path(config["path"]).resolve(),
        config["line"],
        config["inject"],
        config["qualname"],
        config["firstlineno"],
        config.get("kind", "assertion"),
    )
    code = pytest.main(
        [
            "-q",
            "--tb=short",
            "-p",
            "no:cacheprovider",
            "--rootdir",
            config["root"],
            config["nodeid"],
        ],
        plugins=[plugin],
    )
    Path(output).write_text(
        json.dumps(
            {
                "schema": (
                    "factory.call-propagation-challenge.v1"
                    if plugin.kind == "call"
                    else "factory.assertion-propagation-challenge.v1"
                ),
                "exit_code": int(code),
                "hits": plugin.hits,
                "collected": plugin.collected,
                "reports": plugin.reports,
            }
        ),
        encoding="utf-8",
    )


def _challenge_path(root, nodeid):
    root = Path(root).resolve()
    if not isinstance(nodeid, str):
        raise ValueError("An exact pytest node ID is required")
    name = nodeid.split("::", 1)[0]
    if (
        "::" not in nodeid
        or nodeid.startswith("-")
        or "\x00" in nodeid
        or Path(name).is_absolute()
    ):
        raise ValueError("An exact pytest node ID is required")
    path = root / name
    linked = any(
        parent.is_symlink()
        for parent in [path, *path.parents]
        if parent.is_relative_to(root)
    )
    if linked or not path.resolve().is_relative_to(root):
        raise ValueError("Test source must remain inside the project")
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("Test source exceeds the 4 MiB probe limit")
    return root, path.resolve()


def _challenge_inputs(root, nodeid, line):
    root, path = _challenge_path(root, nodeid)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    assertions = [
        n for n in ast.walk(tree) if isinstance(n, ast.Assert) and n.lineno == line
    ]
    ambiguous = _shared_assertion_line(tree, line)
    if type(line) is not int or len(assertions) != 1 or ambiguous:
        raise ValueError("The requested line must contain exactly one Python assert")
    scopes = _assertion_scopes(tree, assertions[0])
    return (
        root,
        path,
        _assertion_qualname(scopes),
        _assertion_firstlineno(scopes),
    )


def _call_challenge_inputs(root, nodeid, line):
    root, path = _challenge_path(root, nodeid)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    expressions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and node.lineno == line
    ]
    statements = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.stmt) and node.lineno == line
    ]
    if type(line) is not int or len(expressions) != 1:
        raise ValueError("The requested line must contain one standalone call")
    expression = expressions[0]
    calls = [node for node in ast.walk(expression.value) if isinstance(node, ast.Call)]
    scopes = _assertion_scopes(tree, expression)
    if (
        not isinstance(expression.value, ast.Call)
        or len(calls) != 1
        or statements != [expression]
        or not any(
            isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            for scope in scopes
        )
    ):
        raise ValueError(
            "The requested line must be one standalone call inside a function"
        )
    return (
        root,
        path,
        _assertion_qualname(scopes),
        _assertion_firstlineno(scopes),
    )


def _assertion_firstlineno(scopes):
    function = next(
        (
            node
            for node in scopes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ),
        None,
    )
    if function is None:
        return 1
    return min(
        [function.lineno, *(decorator.lineno for decorator in function.decorator_list)]
    )


def _shared_assertion_line(tree, line):
    return any(
        isinstance(n, ast.stmt)
        and not isinstance(
            n, (ast.Assert, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        )
        and n.lineno == line
        for n in ast.walk(tree)
    )


def _assertion_scopes(tree, assertion):
    parents = {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }
    scopes, node = [], assertion
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scopes.append(node)
    return scopes


def _assertion_qualname(scopes):
    parts, previous = [], None
    for node in reversed(scopes):
        if parts and isinstance(previous, (ast.FunctionDef, ast.AsyncFunctionDef)):
            parts.append("<locals>")
        parts.append(node.name)
        previous = node
    return ".".join(parts) or "<module>"


def _challenge_source_binding(root):
    """Bind Python sources while excluding dependencies and generated caches."""
    from .review_audits import _security_source_files

    files = _security_source_files(root)
    if len(files) > 4096 or any(
        path.is_symlink() or not path.resolve().is_relative_to(root) for path in files
    ):
        raise ValueError("Source binding exceeds limits or contains links")
    if sum(path.stat().st_size for path in files) > 128 * 1024 * 1024:
        raise ValueError("Source binding exceeds the 128 MiB probe limit")
    return hashlib.sha256(
        json.dumps(
            [
                [
                    path.relative_to(root).as_posix(),
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                ]
                for path in sorted(files)
            ],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _run_assertion_challenge(config, timeout):
    from .runtime_audit_process import _facts, _launch, _run_child_bounded

    with tempfile.TemporaryDirectory(prefix="cf-assertion-probe-") as directory:
        output = Path(directory) / "observation.json"
        script = (
            "import json,sys; sys.path.insert(0,sys.argv.pop(1)); "
            "from factoryline.pytest_readiness import _challenge_worker; "
            "_challenge_worker(json.loads(sys.argv[1]),sys.argv[2])"
        )
        env = dict(os.environ)
        env.pop("PYTEST_CURRENT_TEST", None)
        package_root = str(Path(__file__).resolve().parent.parent)
        env["PYTHONPATH"] = os.pathsep.join([package_root, env.get("PYTHONPATH", "")])
        started = time.monotonic()
        try:
            child = _launch(
                [
                    sys.executable,
                    "-c",
                    script,
                    package_root,
                    json.dumps(config),
                    str(output),
                ],
                Path(config["root"]),
                env,
            )
        except OSError:
            return {"status": "RUNNER_ERROR"}
        facts = _run_child_bounded(
            child, _facts(), timeout, started + timeout, started, None, None, None
        )
        if facts["timed_out"]:
            return {"status": "TIMEOUT"}
        if facts["output_limit_exceeded"] or not facts["cleanup_confirmed"]:
            return {"status": "RUNNER_LIMIT", "process": facts}
        if not output.is_file():
            return {"status": "RUNNER_ERROR", "exit_code": facts["exit_code"]}
        if output.stat().st_size > 1024 * 1024:
            return {"status": "RUNNER_LIMIT", "process": facts}
        return _probe_observation(output, facts)


def _probe_observation(output, facts):
    try:
        observation = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"status": "RUNNER_ERROR", "process": facts}
    if not isinstance(observation, dict):
        return {"status": "RUNNER_ERROR", "process": facts}
    observation["process"] = facts
    return observation


def _exact_challenge_outcome(observation, nodeid, outcome):
    if (
        observation.get("collected") != [nodeid]
        or type(observation.get("hits")) is not int
    ):
        return False
    if observation["hits"] < 1:
        return False
    reports = observation.get("reports", [])
    if observation.get("exit_code") != (0 if outcome == "passed" else 1):
        return False
    return _exact_phase_reports(reports, nodeid, outcome)


def _exact_phase_reports(reports, nodeid, outcome):
    if not isinstance(reports, list) or any(
        not isinstance(row, dict) for row in reports
    ):
        return False
    if [(row.get("nodeid"), row.get("phase")) for row in reports] != [
        (nodeid, phase) for phase in ("setup", "call", "teardown")
    ]:
        return False
    if any(
        row.get("xfail", True) or row.get("outcome") == "skipped" for row in reports
    ):
        return False
    calls = [row for row in reports if row["phase"] == "call"]
    if len(calls) != 1 or calls[0].get("outcome") != outcome:
        return False
    return all(
        row.get("outcome") == "passed" for row in reports if row["phase"] != "call"
    )


def probe_assertion_propagation(root, nodeid, line, *, timeout=30):
    """Execute one test twice to observe assertion reachability and failure escape.

    Explicit local execution, not a sandbox, semantic-oracle proof, independent
    accuracy measurement or authority to clear a scanner finding. Constant and
    otherwise weak assertions can propagate too; callers must assess their intent.
    """
    if type(timeout) not in (int, float) or not 0 < timeout <= 300:
        raise ValueError("timeout must be between 0 and 300 seconds")
    root, path, qualname, firstlineno = _challenge_inputs(root, nodeid, line)
    before = _challenge_source_binding(root)
    config = {
        "root": str(root),
        "path": str(path),
        "line": line,
        "nodeid": nodeid,
        "inject": False,
        "qualname": qualname,
        "firstlineno": firstlineno,
    }
    baseline = _run_assertion_challenge(config, timeout)
    challenge = {}
    baseline_stable = before == _challenge_source_binding(root)
    if baseline_stable and _exact_challenge_outcome(baseline, nodeid, "passed"):
        challenge = _run_assertion_challenge({**config, "inject": True}, timeout)
    stable = baseline_stable and before == _challenge_source_binding(root)
    propagated = _exact_challenge_outcome(challenge, nodeid, "failed")
    visible = propagated and any(
        row.get("challenge_visible") is True
        for row in challenge.get("reports", [])
        if row["phase"] == "call"
    )
    return {
        "schema": "factory.assertion-propagation-probe.v1",
        "status": "OBSERVED" if stable and propagated and visible else "INCOMPLETE",
        "nodeid": nodeid,
        "line": line,
        "assertion_qualname": qualname,
        "source_sha256": before,
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "binding_scope": "Python source inventory only; dependencies and non-Python files are not bound",
        "source_unchanged": stable,
        "semantic_strength": "NOT_ASSESSED",
        "observer_integrity": "IN_PROCESS_NOT_ATTESTED",
        "baseline": baseline,
        "challenge": challenge,
        "limits": [
            "Local supervised execution; no isolation or independent accuracy claim",
            "Trusted project code only; hostile code can alter the in-process observer",
            "Reachability and propagation only; semantic strength is not proved",
            "No automatic finding suppression, approval or release authority",
        ],
    }


def probe_call_propagation(root, nodeid, line, *, timeout=30):
    """Inject before one standalone call to observe execution-point failure escape.

    This does not measure mutation sensitivity of the production function, semantic
    quality, or whether a scanner finding should be cleared. Project code runs locally.
    """
    if type(timeout) not in (int, float) or not 0 < timeout <= 300:
        raise ValueError("timeout must be between 0 and 300 seconds")
    root, path, qualname, firstlineno = _call_challenge_inputs(root, nodeid, line)
    before = _challenge_source_binding(root)
    config = {
        "root": str(root),
        "path": str(path),
        "line": line,
        "nodeid": nodeid,
        "inject": False,
        "qualname": qualname,
        "firstlineno": firstlineno,
        "kind": "call",
    }
    baseline = _run_assertion_challenge(config, timeout)
    challenge = {}
    baseline_stable = before == _challenge_source_binding(root)
    if baseline_stable and _exact_challenge_outcome(baseline, nodeid, "passed"):
        challenge = _run_assertion_challenge({**config, "inject": True}, timeout)
    stable = baseline_stable and before == _challenge_source_binding(root)
    propagated = _exact_challenge_outcome(challenge, nodeid, "failed")
    visible = propagated and any(
        row.get("challenge_visible") is True
        for row in challenge.get("reports", [])
        if row["phase"] == "call"
    )
    return {
        "schema": "factory.call-propagation-probe.v1",
        "status": "OBSERVED" if stable and propagated and visible else "INCOMPLETE",
        "nodeid": nodeid,
        "line": line,
        "call_scope": qualname,
        "source_sha256": before,
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "binding_scope": "Python source inventory only; dependencies and non-Python files are not bound",
        "source_unchanged": stable,
        "execution_point": "Before the selected call statement; reachability and injected failure escape only",
        "production_function_mutation_sensitivity": "NOT_TESTED",
        "semantic_quality": "NOT_ASSESSED",
        "observer_integrity": "IN_PROCESS_NOT_ATTESTED",
        "baseline": baseline,
        "challenge": challenge,
        "limits": [
            "Local supervised execution; no isolation or independent accuracy claim",
            "Trusted project code only; hostile code can alter the in-process observer",
            "The injected failure tests statement reachability and failure escape, not production behavior",
            "No automatic finding suppression, approval or release authority",
        ],
    }


class _Results:
    def __init__(self) -> None:
        self.passed = 0
        self.skipped = 0
        self.xfailed = 0

    def pytest_collectreport(self, report) -> None:
        """Count collection skips that prevent an entire module from running."""
        if report.skipped:
            self.skipped += 1

    def pytest_runtest_logreport(self, report) -> None:
        """Count test outcomes, including setup skips and xfails."""
        if report.skipped:
            if hasattr(report, "wasxfail"):
                self.xfailed += 1
            else:
                self.skipped += 1
        elif report.when == "call" and report.passed:
            if hasattr(report, "wasxfail"):
                self.xfailed += 1
            else:
                self.passed += 1


def collect_pytest_readiness(test_paths: list[str]) -> dict[str, int]:
    """Run strict pytest and count pass, skip, and xfail outcomes across phases."""
    results = _Results()
    # The readiness probe runs a nested pytest session from an arbitrary
    # temporary directory, so the repository's pyproject configuration is not
    # discovered. Preserve the project's fixture-loop setting when
    # pytest-asyncio is available. Let pytest load the plugin normally when
    # autoload is enabled; explicitly pass it only when the caller disabled
    # plugin autoload.
    # Normalize absolute paths for Windows.  Pytest's nested invocation can
    # otherwise treat a backslash-containing drive path as a collection root
    # and walk the protected ``C:\\Documents and Settings`` junction.
    normalized_paths = [Path(path).resolve().as_posix() for path in test_paths]
    # Pin collection to the supplied suite directory.  On Windows, pytest's
    # upward root discovery can otherwise select the drive root and traverse
    # the protected ``Documents and Settings`` junction before it reaches the
    # explicit file path.  The readiness probe only needs the named suites,
    # so a local root is both safer and deterministic.
    probe_root = str(Path(normalized_paths[0]).parent) if normalized_paths else "."
    plugins: list[object] = [results]
    pytest_args = [
        "-q",
        "--strict-markers",
        "--strict-config",
        "--rootdir",
        probe_root,
    ]
    try:
        import pytest_asyncio.plugin
    except ImportError:
        pass
    else:
        pytest_args.extend(["-o", "asyncio_default_fixture_loop_scope=function"])
        if os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD"):
            plugins.append(pytest_asyncio.plugin)
    exit_code = pytest.main(
        [*pytest_args, *normalized_paths],
        plugins=plugins,
    )
    return {
        "exit_code": int(exit_code),
        "passed": results.passed,
        "skipped": results.skipped,
        "xfailed": results.xfailed,
    }


def main(argv=None):
    """Run an explicitly selected local assertion or call propagation probe."""
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Execute one pytest case twice to challenge assertion or call propagation; "
            "runs project code locally."
        )
    )
    parser.add_argument("--root", required=True)
    parser.add_argument("--nodeid", required=True)
    parser.add_argument("--line", required=True, type=int)
    parser.add_argument("--kind", choices=("assertion", "call"), default="assertion")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args(argv)
    probe = (
        probe_call_propagation if args.kind == "call" else probe_assertion_propagation
    )
    result = probe(args.root, args.nodeid, args.line, timeout=args.timeout)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "OBSERVED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
