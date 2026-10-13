"""Exact pytest outcome collection for release-readiness smoke gates."""

from __future__ import annotations

import os
import ast
import hashlib
import importlib.machinery
import json
import sys
import tempfile
import threading
import time
from types import ModuleType

import pytest
from pathlib import Path


class _AssertionChallenge:
    """Observe one assertion during the selected call phase, including new threads."""

    def __init__(
        self,
        path,
        line,
        inject,
        qualname,
        firstlineno,
        kind="assertion",
        attribute_binding=None,
    ):
        self.path, self.line, self.inject = path, line, inject
        self.qualname = qualname
        self.firstlineno = firstlineno
        self.kind = kind
        self.attribute_binding = attribute_binding or {}
        self.attribute_module = {"state": "NOT_APPLICABLE"}
        self.attribute_exception = {}
        self._attribute_module = None
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
                if self.inject and self.kind != "attribute":
                    raise self.error
        return self.trace

    def pytest_runtest_setup(self, item):
        """Validate the imported source module and optionally remove one export."""
        if self.kind != "attribute":
            return
        self.attribute_module, self._attribute_module = _prepare_attribute_module(
            item, self.attribute_binding, self.inject
        )

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
        """Record challenge identity or the exact natural missing-export error."""
        if self.kind == "attribute":
            if self.inject and call.excinfo is not None and call.when == "call":
                self.attribute_exception = _attribute_exception_evidence(
                    call.excinfo.value,
                    call.excinfo.tb,
                    self.path,
                    self.line,
                    self.qualname,
                    self.firstlineno,
                    self._attribute_module,
                    self.attribute_binding.get("export"),
                )
                if self.attribute_exception.get("matches") is True:
                    self.escaped.add((item.nodeid, call.when))
            yield
            return
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
    context_before = _challenge_runtime_context(config["root"])
    plugin = _AssertionChallenge(
        Path(config["path"]).resolve(),
        config["line"],
        config["inject"],
        config["qualname"],
        config["firstlineno"],
        config.get("kind", "assertion"),
        config.get("attribute_binding"),
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
    context_after = _challenge_runtime_context(config["root"])
    Path(output).write_text(
        json.dumps(
            {
                "schema": (
                    {
                        "call": "factory.call-propagation-challenge.v1",
                        "attribute": "factory.attribute-removal-challenge.v1",
                    }.get(plugin.kind, "factory.assertion-propagation-challenge.v1")
                ),
                "exit_code": int(code),
                "hits": plugin.hits,
                "collected": plugin.collected,
                "reports": plugin.reports,
                "attribute_module": plugin.attribute_module,
                "attribute_exception": plugin.attribute_exception,
                "runtime_context_before": context_before,
                "runtime_context_after": context_after,
                "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
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


def _attribute_challenge_inputs(root, nodeid, line):
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
    if type(line) is not int or len(expressions) != 1 or statements != expressions:
        raise ValueError(
            "The requested line must contain one direct module attribute read"
        )
    expression = expressions[0]
    target = expression.value
    scopes = _assertion_scopes(tree, expression)
    functions = [
        scope
        for scope in scopes
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if (
        not isinstance(target, ast.Attribute)
        or not isinstance(target.value, ast.Name)
        or len(functions) != 1
        or functions[0].name != nodeid.split("::")[-1].split("[")[0]
        or not functions[0].name.startswith("test_")
        or functions[0].decorator_list
        or functions[0].args.args
        or functions[0].args.posonlyargs
        or functions[0].args.kwonlyargs
        or functions[0].args.vararg is not None
        or functions[0].args.kwarg is not None
        or not functions[0].body
        or any(
            not isinstance(statement, ast.Expr)
            or not isinstance(statement.value, ast.Attribute)
            or not isinstance(statement.value.value, ast.Name)
            for statement in functions[0].body
        )
    ):
        raise ValueError(
            "The test must contain only direct module attribute read statements"
        )
    alias_name = target.value.id
    if any(statement.value.value.id != alias_name for statement in functions[0].body):
        raise ValueError(
            "All direct attribute reads must use the selected module alias"
        )
    imports = [
        (
            alias,
            alias.asname or alias.name.split(".")[0],
            alias.name if alias.asname else alias.name.split(".")[0],
        )
        for statement in tree.body
        if isinstance(statement, ast.Import)
        for alias in statement.names
    ]
    matches = [row for row in imports if row[1] == alias_name]
    all_aliases = [
        alias
        for statement in ast.walk(tree)
        if isinstance(statement, (ast.Import, ast.ImportFrom))
        for alias in statement.names
        if (alias.asname or alias.name.split(".")[0]) == alias_name
    ]
    stores = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == alias_name
        and isinstance(node.ctx, ast.Store)
    ]
    if len(matches) != 1 or len(all_aliases) != 1 or stores:
        raise ValueError(
            "The attribute root must have one stable module import binding"
        )
    return (
        root,
        path,
        _assertion_qualname(scopes),
        _assertion_firstlineno(scopes),
        {"alias": alias_name, "module_name": matches[0][2], "export": target.attr},
    )


def _attribute_module_facts(item, binding, expected):
    root = Path(item.config.rootpath).resolve()
    module = vars(item.module).get(binding["alias"])
    if type(module) is not ModuleType:
        return None, None, "MODULE_ROOT_NOT_REAL_MODULE"
    namespace = vars(module)
    if module.__name__ != binding["module_name"]:
        return None, None, "MODULE_NAME_MISMATCH"
    if "__getattr__" in namespace:
        return None, None, "DYNAMIC_MODULE_GETATTR"
    if binding["export"] not in namespace:
        return None, None, "BASELINE_EXPORT_MISSING"
    value = namespace[binding["export"]]
    if any(base.__module__ == "unittest.mock" for base in type(value).__mro__):
        return None, None, "MOCK_EXPORT_UNSUPPORTED"
    module_file = namespace.get("__file__")
    spec = namespace.get("__spec__")
    origin = getattr(spec, "origin", None)
    if (
        not isinstance(module_file, str)
        or not isinstance(origin, str)
        or type(getattr(spec, "loader", None))
        is not importlib.machinery.SourceFileLoader
    ):
        return None, None, "MODULE_SOURCE_UNAVAILABLE"
    source, source_bytes, error = _attribute_source_bytes(
        root, Path(module_file), Path(origin)
    )
    if error is not None:
        return None, None, error
    if expected is not None and (
        source.relative_to(root).as_posix() != expected.get("module_path")
        or hashlib.sha256(source_bytes).hexdigest() != expected.get("module_sha256")
    ):
        return None, None, "MODULE_SOURCE_CHANGED"
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    relative = source.relative_to(root).as_posix()
    return (
        {
            "state": "BASELINE_READY",
            "alias": binding["alias"],
            "module_name": module.__name__,
            "module_path": relative,
            "module_sha256": source_sha256,
            "export": binding["export"],
            "export_present_before": True,
            "export_removed": False,
        },
        module,
        None,
    )


def _attribute_source_bytes(root, lexical_source, lexical_origin):
    if lexical_source.is_symlink() or lexical_origin.is_symlink():
        return None, None, "MODULE_SOURCE_NOT_LOCAL"
    try:
        source = lexical_source.resolve(strict=True)
        origin_path = lexical_origin.resolve(strict=True)
        linked_parent = any(
            parent.is_symlink()
            for candidate in (lexical_source, lexical_origin)
            for parent in candidate.parents
            if parent == root or parent.is_relative_to(root)
        )
        if (
            source != origin_path
            or source.suffix != ".py"
            or not source.is_file()
            or not source.is_relative_to(root)
            or linked_parent
        ):
            return None, None, "MODULE_SOURCE_NOT_LOCAL"
        from .review_audits import _security_source_files

        if source not in _security_source_files(root):
            return None, None, "MODULE_SOURCE_NOT_BOUND"
        with source.open("rb") as stream:
            source_bytes = stream.read(4 * 1024 * 1024 + 1)
    except (OSError, RuntimeError, ValueError):
        return None, None, "MODULE_SOURCE_NOT_LOCAL"
    if len(source_bytes) > 4 * 1024 * 1024:
        return None, None, "MODULE_SOURCE_TOO_LARGE"
    return source, source_bytes, None


def _prepare_attribute_module(item, binding, remove_export):
    expected = binding.get("expected_module") if remove_export else None
    facts, module, error = _attribute_module_facts(item, binding, expected)
    if error is not None:
        return {"state": "REJECTED", "reason": error}, None
    if not remove_export:
        return facts, module
    try:
        delattr(module, binding["export"])
    except (AttributeError, TypeError):
        return {"state": "REJECTED", "reason": "EXPORT_REMOVAL_FAILED"}, None
    if binding["export"] in vars(module):
        return {"state": "REJECTED", "reason": "EXPORT_STILL_PRESENT"}, None
    return {**facts, "state": "EXPORT_REMOVED", "export_removed": True}, module


def _attribute_exception_evidence(
    error, tb, path, line, qualname, firstlineno, module, export
):
    frames = []
    while tb is not None:
        frame = tb.tb_frame
        if (
            frame.f_code.co_name == qualname.rsplit(".", 1)[-1]
            and frame.f_code.co_firstlineno == firstlineno
            and Path(frame.f_code.co_filename).resolve() == path
            and tb.tb_lineno == line
        ):
            frames.append(frame)
        tb = tb.tb_next
    type_matches = type(error) is AttributeError
    name_matches = type_matches and getattr(error, "name", None) == export
    object_matches = type_matches and getattr(error, "obj", None) is module
    frame_matches = len(frames) == 1
    return {
        "type": "builtins.AttributeError" if type_matches else None,
        "name_matches": name_matches,
        "object_identity_matches": object_matches,
        "target_frame_matches": frame_matches,
        "matches": type_matches and name_matches and object_matches and frame_matches,
    }


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
    rows = []
    consumed = 0
    for path in sorted(files):
        digest, size = _challenge_source_digest(path, 128 * 1024 * 1024 - consumed)
        consumed += size
        rows.append([path.relative_to(root).as_posix(), digest])
    return hashlib.sha256(
        json.dumps(
            rows,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _challenge_source_digest(path, byte_limit):
    digest = hashlib.sha256()
    consumed = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(min(1024 * 1024, byte_limit - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > byte_limit:
                raise ValueError("Source binding exceeds the 128 MiB probe limit")
            digest.update(chunk)
    return digest.hexdigest(), consumed


def _run_assertion_challenge(config, timeout):
    from .runtime_audit_process import _facts, _launch, _run_child_bounded

    with tempfile.TemporaryDirectory(prefix="cf-assertion-probe-") as directory:
        output = Path(directory) / "observation.json"
        script = (
            "import json,sys; sys.path.insert(0,sys.argv.pop(1)); "
            "from factoryline.pytest_readiness import _challenge_worker; "
            "sys.path.insert(0,json.loads(sys.argv[1])['root']); "
            "_challenge_worker(json.loads(sys.argv[1]),sys.argv[2])"
        )
        env = dict(os.environ)
        env.pop("PYTEST_CURRENT_TEST", None)
        package_root = str(Path(__file__).resolve().parent.parent)
        env["PYTHONPATH"] = os.pathsep.join([package_root, env.get("PYTHONPATH", "")])
        config = {
            **config,
            "launch_context_sha256": _challenge_runtime_context(config["root"], env),
        }
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
            return {
                "status": "RUNNER_LIMIT",
                "process": facts,
                "report_limit_exceeded": True,
                "report_limit_bytes": 1024 * 1024,
            }
        observation = _probe_observation(output, facts)
        if config.get("kind") == "attribute" and isinstance(observation, dict):
            observation["launch_context_sha256"] = config["launch_context_sha256"]
            observation["runtime_context_stable"] = (
                observation.get("runtime_context_before")
                == observation.get("runtime_context_after")
                == config["launch_context_sha256"]
            )
        return observation


def _challenge_runtime_context(root, environment=None):
    """Fingerprint effective collection, interpreter and environment without values."""
    from .review_audits import _pytest_collection_config

    patterns, config = _pytest_collection_config(Path(root).resolve())
    environment = os.environ if environment is None else environment
    env_digest = hashlib.sha256(
        json.dumps(
            sorted(
                (key, hashlib.sha256(value.encode("utf-8")).hexdigest())
                for key, value in environment.items()
                if key != "PYTEST_CURRENT_TEST"
            ),
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    identity = {
        "collection": {**config, "patterns": sorted(patterns)},
        "python": {
            "implementation": sys.implementation.name,
            "version": sys.version,
            "cache_tag": sys.implementation.cache_tag,
            "executable_path_sha256": hashlib.sha256(
                str(Path(sys.executable).resolve()).encode("utf-8")
            ).hexdigest(),
        },
        "pytest_version": pytest.__version__,
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "environment_sha256": env_digest,
    }
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if len(encoded) > 1024 * 1024:
        raise ValueError("Probe runtime context exceeds its size limit")
    return hashlib.sha256(encoded).hexdigest()


def _probe_observation(output, facts):
    try:
        with output.open("rb") as stream:
            payload = stream.read(1024 * 1024 + 1)
        if len(payload) > 1024 * 1024:
            return {
                "status": "RUNNER_LIMIT",
                "process": facts,
                "report_limit_exceeded": True,
                "report_limit_bytes": 1024 * 1024,
            }
        observation = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, ValueError):
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


def _attribute_outcome(observation, nodeid, outcome, module_state):
    return (
        _exact_challenge_outcome(observation, nodeid, outcome)
        and observation.get("hits") == 1
        and observation.get("runtime_context_stable") is True
        and observation.get("attribute_module", {}).get("state") == module_state
    )


def _attribute_probe_config(root, path, nodeid, line, qualname, firstlineno, binding):
    config = {
        "root": str(root),
        "path": str(path),
        "line": line,
        "nodeid": nodeid,
        "inject": False,
        "qualname": qualname,
        "firstlineno": firstlineno,
        "kind": "attribute",
        "attribute_binding": binding,
    }
    return config


def _attribute_probe_baseline(config, before, root, nodeid, binding, timeout):
    baseline = _run_assertion_challenge(config, timeout)
    baseline_stable = before == _challenge_source_binding(root)
    challenge = {}
    baseline_module = baseline.get("attribute_module", {})
    baseline_valid = (
        baseline_stable
        and _attribute_outcome(baseline, nodeid, "passed", "BASELINE_READY")
        and baseline_module.get("export_present_before") is True
    )
    if baseline_valid:
        challenge_config = {
            **config,
            "inject": True,
            "attribute_binding": {**binding, "expected_module": baseline_module},
        }
        challenge = _run_assertion_challenge(challenge_config, timeout)
    return baseline, challenge, baseline_stable, baseline_valid


def _attribute_probe_observation(root, path, nodeid, line, binding, config, timeout):
    before = _challenge_source_binding(root)
    tool_before = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    baseline, challenge, baseline_stable, baseline_valid = _attribute_probe_baseline(
        config, before, root, nodeid, binding, timeout
    )
    stable = baseline_stable and before == _challenge_source_binding(root)
    context_stable = (
        baseline.get("launch_context_sha256") == challenge.get("launch_context_sha256")
        and baseline.get("runtime_context_stable") is True
        and challenge.get("runtime_context_stable") is True
    )
    tool_stable = (
        tool_before == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        and baseline.get("tool_sha256") == tool_before
        and challenge.get("tool_sha256") == tool_before
    )
    natural_failure = (
        _attribute_outcome(challenge, nodeid, "failed", "EXPORT_REMOVED")
        and challenge.get("attribute_exception", {}).get("matches") is True
        and challenge.get("reports", [{}])[1].get("challenge_visible") is True
    )
    observed = (
        stable and context_stable and tool_stable and baseline_valid and natural_failure
    )
    return {
        "schema": "factory.attribute-removal-probe.v1",
        "status": "OBSERVED" if observed else "INCOMPLETE",
        "nodeid": nodeid,
        "line": line,
        "module_alias": binding["alias"],
        "module_name": binding["module_name"],
        "export": binding["export"],
        "source_sha256": before,
        "tool_sha256": tool_before,
        "source_unchanged": stable,
        "runtime_context_unchanged": context_stable,
        "tool_unchanged": tool_stable,
        "semantic_quality": "NOT_ASSESSED",
        "observer_integrity": "IN_PROCESS_NOT_ATTESTED",
        "baseline": baseline,
        "challenge": challenge,
        "limits": [
            "Local supervised execution; no isolation or independent accuracy claim",
            "Only direct in-root module exports without dynamic __getattr__ are supported",
            "The mutation proves exact-line missing-export failure only, not broader semantics",
            "No automatic finding suppression, approval or release authority",
        ],
    }


def probe_attribute_removal(root, nodeid, line, *, timeout=30):
    """Observe one direct imported export read fail after in-memory export removal.

    This is an advisory local mutation check, not a sandbox or finding-clearance
    authority. It supports only one exact module-alias attribute expression.
    """
    if type(timeout) not in (int, float) or not 0 < timeout <= 300:
        raise ValueError("timeout must be between 0 and 300 seconds")
    root, path, qualname, firstlineno, binding = _attribute_challenge_inputs(
        root, nodeid, line
    )
    config = _attribute_probe_config(
        root, path, nodeid, line, qualname, firstlineno, binding
    )
    return _attribute_probe_observation(
        root, path, nodeid, line, binding, config, timeout
    )


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


def _probe_cli_result(probe, args):
    try:
        return probe(args.root, args.nodeid, args.line, timeout=args.timeout)
    except (ValueError, OSError):
        return {
            "schema": "factory.probe-validation.v1",
            "status": "INVALID",
            "kind": args.kind,
            "reason": "Probe inputs or source could not be validated; no observation established.",
        }


def main(argv=None):
    """Run an explicitly selected local assertion or call propagation probe."""
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Execute one selected pytest case to challenge assertion, call, or imported-attribute behavior; "
            "runs project code locally."
        )
    )
    parser.add_argument("--root", required=True)
    parser.add_argument("--nodeid", required=True)
    parser.add_argument("--line", required=True, type=int)
    parser.add_argument(
        "--kind", choices=("assertion", "call", "attribute"), default="assertion"
    )
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args(argv)
    probe = {
        "assertion": probe_assertion_propagation,
        "call": probe_call_propagation,
        "attribute": probe_attribute_removal,
    }[args.kind]
    result = _probe_cli_result(probe, args)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "OBSERVED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
