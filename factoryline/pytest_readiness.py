"""Exact pytest outcome collection for release-readiness smoke gates."""

from __future__ import annotations

import os
import ast
import configparser
import hashlib
import importlib.metadata
import importlib.machinery
import importlib.util
import io
import json
import math
import re
import sys
import tempfile
import threading
import time
import tokenize
from types import CodeType, ModuleType

import pytest
from pathlib import Path


def _mutation_failure_visible(excinfo, path, line, qualname, firstlineno):
    if excinfo is None or not isinstance(excinfo.value, AssertionError):
        return False
    entry = excinfo.traceback[-1]
    code = entry.frame.raw.f_code
    code_qualname = getattr(code, "co_qualname", None)
    return (
        Path(str(entry.path)).resolve() == path
        and entry.lineno + 1 == line
        and code.co_name == qualname.rsplit(".", 1)[-1]
        and (code_qualname is None or code_qualname == qualname)
        and code.co_firstlineno == firstlineno
    )


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
        root=None,
        source_manifest=None,
        allow_multiple=False,
        nodeid=None,
    ):
        self.path, self.line, self.inject = path, line, inject
        self.qualname = qualname
        self.firstlineno = firstlineno
        self.kind = kind
        self.attribute_binding = attribute_binding or {}
        self.root = Path(root).resolve() if root else self.path.parent
        self.source_manifest = dict(source_manifest or {})
        self.module_aliases = _challenge_module_aliases(self.source_manifest)
        self.trusted_modules = {
            name: (module, getattr(module, "__file__", None))
            for name in ("factoryline", "factoryline.pytest_readiness")
            if (module := sys.modules.get(name)) is not None
        }
        self.source_filenames = {
            os.path.normcase(str((self.root / relative).resolve()))
            for relative in self.source_manifest
        }
        self.origins = []
        self._origin_seen = set()
        self._frame_name_cache = {}
        self._frame_identity_cache = {}
        self.origin_limit_exceeded = False
        self.origin_status = "BOUND"
        self.phase = "collection"
        self.attribute_module = {"state": "NOT_APPLICABLE"}
        self.attribute_exception = {}
        self._attribute_module = None
        self.active = False
        self.hits = 0
        self.case_hits = {}
        self.assertion_observations = []
        self.collection_incomplete = False
        self.collection_reports = []
        self.current_nodeid = None
        self.allow_multiple = allow_multiple
        self.nodeid = nodeid
        self.reports = []
        self.collected = []
        label = "CALL" if kind == "call" else "ASSERTION"
        self.error = AssertionError(f"CF_{label}_PROPAGATION_CHALLENGE")
        self.escaped = set()

    def trace(self, frame, event, arg):
        """Raise at the reviewed assertion during the selected call phase."""
        self._record_project_frame(frame)
        if self._assertion_target(frame, event):
            self._record_assertion_hit()
        return self.trace

    def _assertion_target(self, frame, event):
        return (
            self.active
            and self.phase == "call"
            and event == "line"
            and frame.f_lineno == self.line
            and frame.f_code.co_name == self.qualname.rsplit(".", 1)[-1]
            and frame.f_code.co_firstlineno == self.firstlineno
            and Path(frame.f_code.co_filename).resolve() == self.path
        )

    def _record_assertion_hit(self):
        self.hits += 1
        if self.current_nodeid is not None:
            self.case_hits[self.current_nodeid] = (
                self.case_hits.get(self.current_nodeid, 0) + 1
            )
        if self.inject and self.kind != "attribute":
            raise self.error

    def _record_project_frame(self, frame):
        if not self._project_frame_relevant(frame):
            return
        name = frame.f_globals.get("__name__")
        module = sys.modules.get(name)
        nodeid = self.current_nodeid or (self.collected[0] if self.collected else "")
        frame_identity = _challenge_frame_identity(
            frame,
            self.root,
            self.source_manifest,
            self._frame_identity_cache,
            self._frame_name_cache,
        )
        frame_qualname = frame_identity[0] if frame_identity else None
        frame_firstlineno = frame_identity[1] if frame_identity else None
        if not self._remember_project_frame_identity(
            frame, nodeid, name, frame_qualname, frame_firstlineno
        ):
            return
        self._store_project_frame_origin(
            name,
            module,
            nodeid,
            frame,
            frame_qualname,
            frame_firstlineno,
            frame_identity is not None,
        )

    def _remember_project_frame_identity(
        self, frame, nodeid, name, frame_qualname, frame_firstlineno
    ):
        key = (
            self.phase,
            nodeid,
            name,
            frame.f_code.co_filename,
            frame_qualname or frame.f_code.co_name,
            frame_firstlineno or frame.f_code.co_firstlineno,
            frame.f_code if frame_qualname is None else None,
        )
        if key in self._origin_seen:
            return False
        if not self._remember_origin(key):
            return False
        self._origin_seen.add(key)

        return True

    def _store_project_frame_origin(
        self,
        name,
        module,
        nodeid,
        frame,
        frame_qualname,
        frame_firstlineno,
        identity_bound,
    ):
        row = _challenge_module_origin(
            name,
            module,
            self.root,
            self.source_manifest,
            nodeid,
            self.phase,
            frame.f_code.co_filename,
            "executed_frame",
            self.module_aliases,
        )
        if row is None:
            self._record_unbound_project_frame(
                name, frame, frame_qualname, frame_firstlineno
            )
            return
        row["frame_qualname"] = frame_qualname
        row["frame_firstlineno"] = frame_firstlineno
        if not identity_bound and row["status"] == "BOUND":
            row["status"] = "INCOMPLETE"
        self._add_origin(row)

    def _project_frame_relevant(self, frame):
        if not self.active or frame.f_code.co_filename.startswith("<"):
            return False
        name = frame.f_globals.get("__name__")
        filename = os.path.normcase(os.path.abspath(frame.f_code.co_filename))
        module = sys.modules.get(name)
        return not self._trusted_harness_origin(name, module) and (
            name in self.module_aliases or filename in self.source_filenames
        )

    def _record_unbound_project_frame(
        self, name, frame, frame_qualname, frame_firstlineno
    ):
        self.origin_status = "INCOMPLETE"
        try:
            source = Path(frame.f_code.co_filename).resolve(strict=True)
            if source.is_relative_to(self.root) and source.suffix == ".py":
                relative = source.relative_to(self.root).as_posix()
                self._add_origin(
                    {
                        "nodeid": self.current_nodeid or "",
                        "phase": self.phase,
                        "module_name": name,
                        "observation_kind": "executed_frame",
                        "origin": relative,
                        "path": relative,
                        "source_sha256": None,
                        "loader": None,
                        "frame_qualname": frame_qualname,
                        "frame_firstlineno": frame_firstlineno,
                        "status": "INCOMPLETE",
                    }
                )
        except (OSError, RuntimeError):
            self.origin_status = "INCOMPLETE"

    def profile(self, frame, event, arg):
        """Observe executed frames from the audited project during profiling."""
        if event == "call":
            self._record_project_frame(frame)

    def _add_origin(self, row):
        if row["status"] != "BOUND":
            self.origin_status = row["status"]
        if row in self.origins:
            return
        if len(self.origins) >= 512:
            self.origin_status = "INCOMPLETE"
            self.origin_limit_exceeded = True
            return
        self.origins.append(row)

    def _remember_origin(self, key):
        if len(self._origin_seen) >= 2048:
            self.origin_status = "INCOMPLETE"
            self.origin_limit_exceeded = True
            return False
        return True

    def _relevant_module(self, name, module):
        if self._trusted_harness_origin(name, module):
            return False
        if name in self.module_aliases:
            return True
        spec = getattr(module, "__spec__", None)
        return any(
            value and os.path.normcase(os.path.abspath(value)) in self.source_filenames
            for value in (
                getattr(spec, "origin", None),
                getattr(module, "__file__", None),
            )
        )

    def _trusted_harness_origin(self, name, module):
        """Ignore only the exact module objects loaded before the probe starts."""
        trusted = self.trusted_modules.get(name)
        if trusted is None or module is not trusted[0] or not trusted[1]:
            return False
        try:
            return Path(getattr(module, "__file__", "")).resolve(strict=True) == Path(
                trusted[1]
            ).resolve(strict=True)
        except (OSError, RuntimeError):
            return False

    def _record_imported_project_modules(self):
        nodeid = self.collected[0] if self.collected else ""
        for name, module in tuple(sys.modules.items()):
            if not self._relevant_module(name, module):
                continue
            key = ("collection", name, getattr(module, "__file__", None))
            if key in self._origin_seen:
                continue
            if not self._remember_origin(key):
                return
            self._origin_seen.add(key)
            row = _challenge_module_origin(
                name,
                module,
                self.root,
                self.source_manifest,
                nodeid,
                "collection",
                aliases=self.module_aliases,
            )
            if row is not None:
                self._add_origin(row)

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
        if not self.collected:
            self.collection_incomplete = True
            raise pytest.UsageError("The selected test function collected no cases")
        if not self.allow_multiple and len(session.items) != 1:
            raise pytest.UsageError(
                "Propagation probes require exactly one collected case"
            )
        for row in self.origins:
            if row["phase"] == "collection" and not row["nodeid"]:
                row["nodeid"] = self.collected[0]
        self._record_imported_project_modules()

    def pytest_deselected(self, items):
        """Mark filtered selected-function cases incomplete before execution."""
        if any(
            item.nodeid == self.nodeid or item.nodeid.startswith(self.nodeid + "[")
            for item in items
        ):
            self.collection_incomplete = True

    def pytest_collectreport(self, report):
        """Record failed or skipped collection reports as incomplete evidence."""
        if report.failed or report.skipped:
            self.collection_incomplete = True
        self.collection_reports.append(
            {
                "nodeid": str(report.nodeid),
                "outcome": str(report.outcome),
                "failed": bool(report.failed),
                "skipped": bool(report.skipped),
                "longrepr_sha256": hashlib.sha256(
                    str(report.longrepr).encode("utf-8", errors="replace")
                ).hexdigest()
                if report.failed or report.skipped
                else None,
            }
        )

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_call(self, item):
        """Trace only the selected call phase and restore existing observers."""
        old, old_thread = sys.gettrace(), threading.gettrace()
        old_profile, old_thread_profile = sys.getprofile(), threading.getprofile()
        self.active = True
        self.current_nodeid = item.nodeid
        self.phase = "call"
        sys.settrace(self.trace)
        threading.settrace(self.trace)
        sys.setprofile(self.profile)
        threading.setprofile(self.profile)
        try:
            yield
        finally:
            self.active = False
            self.current_nodeid = None
            self.phase = "collection"
            sys.settrace(old)
            threading.settrace(old_thread)
            sys.setprofile(old_profile)
            threading.setprofile(old_thread_profile)

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
        if self.allow_multiple and call.when == "call":
            self._record_mutation_assertion(item, call)
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

    def _record_mutation_assertion(self, item, call):
        visible = _mutation_failure_visible(
            call.excinfo, self.path, self.line, self.qualname, self.firstlineno
        )
        self.assertion_observations.append(
            {
                "case_id": item.nodeid,
                "callback_qualname": self.qualname,
                "line": self.line,
                "assertion_kind": "assert",
                "hits": self.case_hits.get(item.nodeid, 0),
                "outcome": "PASS" if call.excinfo is None else "FAIL",
                "failure_visible": visible,
            }
        )


def _challenge_module_aliases(source_manifest):
    aliases = {}
    for relative in source_manifest:
        parts = Path(relative).with_suffix("").parts
        candidates = [parts, parts[1:]] if parts[:1] == ("src",) else [parts]
        for candidate in candidates:
            if candidate and candidate[-1] == "__init__":
                candidate = candidate[:-1]
            if candidate:
                aliases.setdefault(".".join(candidate), set()).add(relative)
    return aliases


def _challenge_origin_components(module, frame_path):
    spec = getattr(module, "__spec__", None)
    spec_origin = getattr(spec, "origin", None)
    module_file = getattr(module, "__file__", None)
    candidates = [value for value in (spec_origin, module_file, frame_path) if value]
    return spec, spec_origin, module_file, candidates


def _challenge_origin_paths(candidates, root):
    paths = [Path(value) for value in candidates]
    try:
        resolved = [path.resolve(strict=True) for path in paths]
        project_paths = [path for path in resolved if path.is_relative_to(root)]
    except (OSError, RuntimeError):
        project_paths = []
        resolved = []
    return resolved, project_paths


def _challenge_external_origin(
    name, nodeid, phase, observation_kind, spec, path, digest=None
):
    return {
        "nodeid": nodeid,
        "phase": phase,
        "module_name": name,
        "observation_kind": observation_kind,
        "origin": "external",
        "origin_sha256": hashlib.sha256(str(path).encode("utf-8")).hexdigest(),
        "path": None,
        "source_sha256": digest,
        "loader": type(getattr(spec, "loader", None)).__name__,
        "status": "MISMATCH",
    }


def _challenge_project_origin(root, source_manifest, resolved, expected):
    origin = resolved[0]
    relative = digest = None
    if len(set(resolved)) != 1 or origin.suffix != ".py":
        return relative, digest, "MISMATCH"
    try:
        relative = origin.relative_to(root).as_posix()
        digest, size = _challenge_source_digest(origin, 4 * 1024 * 1024)
    except (OSError, ValueError, RuntimeError):
        return None, None, "INCOMPLETE"
    status = (
        "BOUND"
        if relative in source_manifest
        and source_manifest[relative] == digest
        and size <= 4 * 1024 * 1024
        else "MISMATCH"
    )
    if expected and relative not in expected and status == "BOUND":
        status = "MISMATCH"
    return relative, digest, status


def _challenge_external_expected(
    name,
    nodeid,
    phase,
    observation_kind,
    spec,
    spec_origin,
    module_file,
    frame_path,
    project_paths,
    expected,
    relative,
    digest,
):
    if not project_paths:
        if not expected:
            return None, True
        return (
            _challenge_external_origin(
                name, nodeid, phase, observation_kind, spec, spec_origin or module_file
            ),
            True,
        )
    if expected and relative not in expected:
        return (
            _challenge_external_origin(
                name,
                nodeid,
                phase,
                observation_kind,
                spec,
                spec_origin or module_file or frame_path,
                digest,
            ),
            True,
        )
    return None, False


def _challenge_module_origin(
    name,
    module,
    root,
    source_manifest,
    nodeid,
    phase,
    frame_path=None,
    observation_kind="imported_module",
    aliases=None,
):
    if module is None or not name:
        return None
    spec, spec_origin, module_file, candidates = _challenge_origin_components(
        module, frame_path
    )
    if not candidates or any(value in ("built-in", "frozen") for value in candidates):
        return None
    resolved, project_paths = _challenge_origin_paths(candidates, root)
    expected = (aliases or _challenge_module_aliases(source_manifest)).get(name, set())
    if not project_paths:
        external, complete = _challenge_external_expected(
            name,
            nodeid,
            phase,
            observation_kind,
            spec,
            spec_origin,
            module_file,
            frame_path,
            project_paths,
            expected,
            None,
            None,
        )
        return external if complete else None
    relative, digest, status = _challenge_project_origin(
        root, source_manifest, resolved, expected
    )
    external, complete = _challenge_external_expected(
        name,
        nodeid,
        phase,
        observation_kind,
        spec,
        spec_origin,
        module_file,
        frame_path,
        project_paths,
        expected,
        relative,
        digest,
    )
    if complete:
        return external
    return {
        "nodeid": nodeid,
        "phase": phase,
        "module_name": name,
        "observation_kind": observation_kind,
        "origin": relative,
        "path": relative,
        "source_sha256": digest,
        "loader": type(getattr(spec, "loader", None)).__name__,
        "status": status,
    }


def _challenge_frame_identity(frame, root, source_manifest, identity_cache, name_cache):
    code = frame.f_code
    if code in identity_cache:
        return identity_cache[code]
    if len(identity_cache) >= 2048:
        return None
    firstlineno = code.co_firstlineno
    try:
        source = Path(code.co_filename).resolve(strict=True)
        relative = source.relative_to(root).as_posix()
        expected = source_manifest[relative]
    except (KeyError, OSError, ValueError, RuntimeError):
        identity_cache[code] = None
        return None
    cache_key = (relative, expected)
    if cache_key not in name_cache:
        if len(name_cache) >= 512:
            identity_cache[code] = None
            return None
        name_cache[cache_key] = _challenge_frame_name_map(source, expected)
    names = name_cache[cache_key]
    qualname = names.get((code.co_name, firstlineno)) if names else None
    runtime_qualname = getattr(code, "co_qualname", None)
    if not qualname or (runtime_qualname and runtime_qualname != qualname):
        identity_cache[code] = None
        return None
    identity = (qualname, firstlineno)
    identity_cache[code] = identity
    return identity


def _challenge_frame_name_map(path, expected_digest):
    try:
        if _typecheck_path_chain_linked(path):
            return {}
        with path.open("rb") as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        if (
            len(raw) > 4 * 1024 * 1024
            or hashlib.sha256(raw).hexdigest() != expected_digest
        ):
            return {}
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        source = raw.decode(encoding)
        compiled = compile(source, str(path), "exec")
        if hasattr(compiled, "co_qualname"):
            return _challenge_compiled_frame_names(compiled)
        tree = ast.parse(source)
        names = {}
        _challenge_collect_ast_frame_names(tree, (), names)
        return names
    except (
        OSError,
        SyntaxError,
        UnicodeError,
        ValueError,
        LookupError,
        RecursionError,
    ):
        return {}


def _challenge_compiled_frame_names(root_code):
    names = {}
    pending = [root_code]
    visited = 0
    while pending:
        code = pending.pop()
        visited += 1
        if visited > 2048:
            return {}
        key = (code.co_name, code.co_firstlineno)
        names[key] = None if key in names else code.co_qualname
        pending.extend(value for value in code.co_consts if isinstance(value, CodeType))
    return names


def _challenge_collect_ast_frame_names(node, scopes, names):
    code_name, scope_name, is_function = _challenge_ast_frame_scope(node)
    if code_name is not None:
        qualname = _challenge_ast_qualname(scopes, scope_name)
        for line in _challenge_ast_frame_lines(node):
            key = (code_name, line)
            names[key] = qualname if key not in names else None
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        _challenge_collect_ast_definition_children(
            node, scopes, scopes + ((scope_name, is_function),), names
        )
        return
    if isinstance(node, ast.Lambda):
        _challenge_collect_ast_lambda_children(
            node, scopes, scopes + ((scope_name, is_function),), names
        )
        return
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        _challenge_collect_ast_comprehension_children(
            node, scopes, scopes + ((scope_name, is_function),), names
        )
        return
    next_scopes = (
        scopes + ((scope_name, is_function),)
        if code_name and not isinstance(node, ast.Module)
        else scopes
    )
    for child in ast.iter_child_nodes(node):
        _challenge_collect_ast_frame_names(child, next_scopes, names)


def _challenge_collect_ast_definition_children(node, outer_scopes, inner_scopes, names):
    for child in ast.iter_child_nodes(node):
        child_scopes = inner_scopes if child in node.body else outer_scopes
        _challenge_collect_ast_frame_names(child, child_scopes, names)


def _challenge_collect_ast_lambda_children(node, outer_scopes, inner_scopes, names):
    _challenge_collect_ast_frame_names(node.body, inner_scopes, names)
    for argument in node.args.defaults + node.args.kw_defaults:
        if argument is not None:
            _challenge_collect_ast_frame_names(argument, outer_scopes, names)


def _challenge_collect_ast_comprehension_children(
    node, outer_scopes, inner_scopes, names
):
    for index, generator in enumerate(node.generators):
        iterable_scopes = outer_scopes if index == 0 else inner_scopes
        _challenge_collect_ast_frame_names(generator.iter, iterable_scopes, names)
        _challenge_collect_ast_frame_names(generator.target, inner_scopes, names)
        for condition in generator.ifs:
            _challenge_collect_ast_frame_names(condition, inner_scopes, names)
    result_nodes = (
        (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)
    )
    for result_node in result_nodes:
        _challenge_collect_ast_frame_names(result_node, inner_scopes, names)


def _challenge_ast_frame_scope(node):
    if isinstance(node, ast.Module):
        return "<module>", "<module>", False
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name, node.name, not isinstance(node, ast.ClassDef)
    if isinstance(node, ast.Lambda):
        return "<lambda>", "<lambda>", True
    for node_type, code_name in (
        (ast.ListComp, "<listcomp>"),
        (ast.SetComp, "<setcomp>"),
        (ast.DictComp, "<dictcomp>"),
        (ast.GeneratorExp, "<genexpr>"),
    ):
        if isinstance(node, node_type):
            return code_name, code_name, False
    return None, None, False


def _challenge_ast_qualname(scopes, name):
    parts = []
    for index, (scope_name, _) in enumerate(scopes):
        if index and scopes[index - 1][1]:
            parts.append("<locals>")
        parts.append(scope_name)
    if scopes and scopes[-1][1]:
        parts.append("<locals>")
    parts.append(name)
    return ".".join(parts)


def _challenge_ast_frame_lines(node):
    if isinstance(node, ast.Module):
        return {1}
    lines = {node.lineno}
    lines.update(decorator.lineno for decorator in getattr(node, "decorator_list", ()))
    return lines


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
    runtime_paths = config.get("runtime_environment_paths")
    normalized_before = (
        _challenge_runtime_context(config["root"], normalized_paths=runtime_paths)
        if runtime_paths
        else None
    )
    manifest_path = Path(config["source_manifest_path"])
    if manifest_path.stat().st_size > 1024 * 1024:
        raise ValueError("Source manifest exceeds its 1 MiB limit")
    source_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    plugin = _AssertionChallenge(
        Path(config["path"]).resolve(),
        config["line"],
        config["inject"],
        config["qualname"],
        config["firstlineno"],
        config.get("kind", "assertion"),
        config.get("attribute_binding"),
        config["root"],
        source_manifest,
        config.get("allow_multiple", False),
        config["nodeid"],
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
    normalized_after = (
        _challenge_runtime_context(config["root"], normalized_paths=runtime_paths)
        if runtime_paths
        else None
    )
    output_path = Path(output)
    if _typecheck_path_chain_linked(output_path) or output_path.exists():
        raise ValueError("Observation destination changed during probe")
    output_path.write_text(
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
                "case_hits": plugin.case_hits,
                "assertion_observations": plugin.assertion_observations,
                "collected": plugin.collected,
                "collection_incomplete": plugin.collection_incomplete,
                "collection_reports": plugin.collection_reports,
                "collection_report_sha256": hashlib.sha256(
                    json.dumps(
                        {
                            "selected": config["nodeid"],
                            "collected": plugin.collected,
                            "reports": plugin.collection_reports,
                            "incomplete": plugin.collection_incomplete,
                        },
                        sort_keys=True,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest(),
                "reports": plugin.reports,
                "executed_modules": plugin.origins,
                "origin_status": plugin.origin_status,
                "origin_limit_exceeded": plugin.origin_limit_exceeded,
                "executed_source_manifest_sha256": hashlib.sha256(
                    json.dumps(
                        plugin.source_manifest, sort_keys=True, separators=(",", ":")
                    ).encode()
                ).hexdigest(),
                "attribute_module": plugin.attribute_module,
                "attribute_exception": plugin.attribute_exception,
                "runtime_context_before": context_before,
                "runtime_context_after": context_after,
                "runtime_context_normalized_before": normalized_before,
                "runtime_context_normalized_after": normalized_after,
                "runtime_environment_mapping": _challenge_runtime_mapping(
                    runtime_paths
                ),
                "python_runtime": {
                    "implementation": sys.implementation.name,
                    "version": sys.version,
                },
                "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            }
        ),
        encoding="utf-8",
    )


def _challenge_path(root, nodeid):
    root = Path(root)
    if _typecheck_path_chain_linked(root):
        raise ValueError("Project root contains a linked path")
    root = root.resolve()
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
    linked = _typecheck_path_chain_linked(path)
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
    rows = [list(row) for row in _challenge_source_inventory(root).items()]
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def _challenge_source_inventory(root):
    """Return bounded path/hash pairs for the audited Python source inventory."""
    from .review_audits import _security_source_files

    files = _security_source_files(root)
    if len(files) > 4096 or any(
        _typecheck_path_chain_linked(path) or not path.resolve().is_relative_to(root)
        for path in files
    ):
        raise ValueError("Source binding exceeds limits or contains links")
    if sum(path.stat().st_size for path in files) > 128 * 1024 * 1024:
        raise ValueError("Source binding exceeds the 128 MiB probe limit")
    rows = {}
    consumed = 0
    for path in sorted(files):
        digest, size = _challenge_source_digest(path, 128 * 1024 * 1024 - consumed)
        consumed += size
        rows[path.relative_to(root).as_posix()] = digest
    return rows


def _challenge_source_digest(path, byte_limit):
    if byte_limit < 0:
        raise ValueError("Source binding exceeds its byte budget")
    if _typecheck_path_chain_linked(path):
        raise ValueError("Source binding path contains a linked ancestor")
    digest = hashlib.sha256()
    consumed = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(min(1024 * 1024, byte_limit - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > byte_limit:
                raise ValueError("Source binding exceeds its byte budget")
            digest.update(chunk)
    return digest.hexdigest(), consumed


def _run_assertion_challenge(config, timeout):
    from .runtime_audit_process import _facts, _launch, _run_child_bounded

    config = dict(config)
    with tempfile.TemporaryDirectory(prefix="cf-assertion-probe-") as directory:
        scratch = _runner_temp_root(directory)
        output = scratch / "observation.json"
        manifest_path = scratch / "source-manifest.json"
        source_manifest = _challenge_runner_manifest(config)
        if source_manifest is None:
            return {
                "status": "INCOMPLETE",
                "source_manifest_status": "INCOMPLETE",
            }
        manifest_path.write_text(
            json.dumps(source_manifest, sort_keys=True), encoding="utf-8"
        )
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
            "source_manifest_path": str(manifest_path),
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
        failure = _challenge_runner_failure(output, facts)
        if failure is not None:
            return failure
        observation = _probe_observation(output, facts)
        if config.get("kind") == "attribute" and isinstance(observation, dict):
            observation["launch_context_sha256"] = config["launch_context_sha256"]
            observation["runtime_context_stable"] = (
                observation.get("runtime_context_before")
                == observation.get("runtime_context_after")
                == config["launch_context_sha256"]
            )
        return observation


def _runner_temp_root(directory):
    """Canonicalize only a root returned by tempfile.TemporaryDirectory."""
    path = Path(directory).resolve(strict=True)
    if not path.is_dir():
        raise ValueError("Runner temporary root is not a directory")
    return path


def _challenge_runner_manifest(config):
    """Use supplied inventory or bind a bounded real inventory for internal callers."""
    if "source_manifest" not in config:
        try:
            return _challenge_source_inventory(Path(config["root"]))
        except (KeyError, OSError, RuntimeError, TypeError, ValueError):
            return None
    manifest = config.pop("source_manifest")
    if not isinstance(manifest, dict) or not manifest:
        return None
    if any(
        not isinstance(path, str)
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        for path, digest in manifest.items()
    ):
        return None
    return manifest


def _challenge_runner_failure(output, facts):
    """Classify bounded worker failures before reading the observation file."""
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
    return None


def _challenge_runtime_mapping(paths):
    """Record only role names and hashes for runner-owned temporary paths."""
    roles = {
        "HOME": "runtime_home",
        "USERPROFILE": "runtime_home",
        "TMP": "runtime_temp",
        "TEMP": "runtime_temp",
        "TMPDIR": "runtime_temp",
    }
    if paths is None:
        return None
    return [
        {
            "name": name,
            "role": roles[name],
            "path_sha256": hashlib.sha256(paths[name].encode("utf-8")).hexdigest(),
        }
        for name in sorted(roles)
    ]


def _challenge_runtime_context(root, environment=None, normalized_paths=None):
    """Fingerprint effective collection, interpreter and environment without values."""
    from .review_audits import _pytest_collection_config

    patterns, config = _pytest_collection_config(Path(root).resolve())
    environment = os.environ if environment is None else environment
    env_digest = _challenge_environment_digest(environment, normalized_paths)
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


def _challenge_environment_digest(environment, normalized_paths):
    roles = {
        "HOME": "runtime_home",
        "USERPROFILE": "runtime_home",
        "TMP": "runtime_temp",
        "TEMP": "runtime_temp",
        "TMPDIR": "runtime_temp",
    }
    if normalized_paths is not None:
        if set(normalized_paths) != set(roles):
            raise ValueError("Runtime path mapping is incomplete")
        if any(
            key not in environment or environment[key] != normalized_paths[key]
            for key in roles
        ):
            raise ValueError("Runtime path mapping does not match the child")
    values = []
    for key, value in sorted(environment.items()):
        if key == "PYTEST_CURRENT_TEST":
            continue
        if normalized_paths is not None and key in normalized_paths:
            value = f"<factory:{roles[key]}>"
        values.append((key, hashlib.sha256(value.encode("utf-8")).hexdigest()))
    return hashlib.sha256(
        json.dumps(values, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


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


def _challenge_origin_observation_bound(observation, manifest):
    return (
        observation.get("origin_status") == "BOUND"
        and observation.get("origin_limit_exceeded") is False
        and isinstance(observation.get("executed_modules"), list)
        and bool(observation.get("executed_modules"))
        and observation.get("executed_source_manifest_sha256")
        == _challenge_manifest_hash(manifest)
    )


def _challenge_manifest_hash(manifest):
    value = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(value).hexdigest()


def _challenge_origin_row_shape_valid(row, nodeid):
    return (
        isinstance(row, dict)
        and row.get("nodeid") == nodeid
        and row.get("phase") in {"collection", "call"}
        and row.get("status") == "BOUND"
        and row.get("observation_kind") in {"imported_module", "executed_frame"}
        and (
            row.get("observation_kind") != "executed_frame"
            or _challenge_origin_frame_identity_valid(row)
        )
    )


def _challenge_origin_frame_identity_valid(row):
    firstlineno = row.get("frame_firstlineno")
    return (
        isinstance(row.get("frame_qualname"), str)
        and bool(row["frame_qualname"])
        and isinstance(firstlineno, int)
        and not isinstance(firstlineno, bool)
        and firstlineno > 0
    )


def _challenge_origin_row_source_bound(row, root, manifest):
    relative = row.get("path")
    if relative not in manifest or manifest[relative] != row.get("source_sha256"):
        return False
    try:
        resolved = (root / relative).resolve(strict=True)
        if not resolved.is_relative_to(root) or resolved.is_symlink():
            return False
        digest, _ = _challenge_source_digest(resolved, 4 * 1024 * 1024)
    except (OSError, ValueError, RuntimeError):
        return False
    return digest == row["source_sha256"] and relative == row.get("origin")


def _challenge_origin_rows_bound(rows, root, manifest, nodeid, expected_path):
    seen_source = False
    for row in rows:
        if not _challenge_origin_row_shape_valid(row, nodeid):
            return False
        if not _challenge_origin_row_source_bound(row, root, manifest):
            return False
        seen_source |= _challenge_origin_is_target_frame(row, expected_path)
    return seen_source


def _challenge_origin_is_target_frame(row, expected_path):
    return (
        row.get("path") == expected_path
        and row["observation_kind"] == "executed_frame"
        and row["phase"] == "call"
    )


def _challenge_origins_bound(observation, root, manifest, nodeid, source_path):
    if not _challenge_origin_observation_bound(observation, manifest):
        return False
    expected_path = Path(source_path).relative_to(root).as_posix()
    return _challenge_origin_rows_bound(
        observation["executed_modules"], root, manifest, nodeid, expected_path
    )


def _propagation_probe_inputs(root, nodeid, line, kind):
    selector = _call_challenge_inputs if kind == "call" else _challenge_inputs
    root, path, qualname, firstlineno = selector(root, nodeid, line)
    manifest = _challenge_source_inventory(root)
    before = _challenge_source_binding(root)
    config = {
        "root": str(root),
        "path": str(path),
        "line": line,
        "nodeid": nodeid,
        "inject": False,
        "qualname": qualname,
        "firstlineno": firstlineno,
        "source_manifest": manifest,
    }
    if kind == "call":
        config["kind"] = kind
    return root, path, qualname, manifest, before, config


def _propagation_baseline_valid(baseline, root, manifest, nodeid, path, stable):
    return (
        stable
        and _challenge_origins_bound(baseline, root, manifest, nodeid, path)
        and _exact_challenge_outcome(baseline, nodeid, "passed")
    )


def _propagation_probe_phases(root, path, nodeid, manifest, before, config, timeout):
    baseline = _run_assertion_challenge(config, timeout)
    baseline_stable = before == _challenge_source_binding(root)
    challenge = {}
    if _propagation_baseline_valid(
        baseline, root, manifest, nodeid, path, baseline_stable
    ):
        challenge = _run_assertion_challenge({**config, "inject": True}, timeout)
    challenge_bound = _challenge_origins_bound(challenge, root, manifest, nodeid, path)
    stable = baseline_stable and before == _challenge_source_binding(root)
    return baseline, challenge, stable, challenge_bound


def _propagation_probe_status(
    root, path, nodeid, manifest, baseline, challenge, stable, challenge_bound
):
    baseline_bound = _challenge_origins_bound(baseline, root, manifest, nodeid, path)
    propagated = _exact_challenge_outcome(challenge, nodeid, "failed")
    visible = propagated and any(
        row.get("challenge_visible") is True
        for row in challenge.get("reports", [])
        if row["phase"] == "call"
    )
    module_bound = baseline_bound and challenge_bound
    return {
        "status": "OBSERVED"
        if stable and propagated and visible and module_bound
        else "INCOMPLETE",
        "source_manifest_status": "BOUND" if stable else "INCOMPLETE",
        "module_origin_status": "BOUND" if module_bound else "INCOMPLETE",
    }


def _propagation_probe_result(
    kind, nodeid, line, before, qualname, pair, root, path, manifest
):
    baseline, challenge, stable, challenge_bound = pair
    status = _propagation_probe_status(
        root, path, nodeid, manifest, baseline, challenge, stable, challenge_bound
    )
    result = {
        "schema": (
            "factory.call-propagation-probe.v1"
            if kind == "call"
            else "factory.assertion-propagation-probe.v1"
        ),
        **status,
        "nodeid": nodeid,
        "line": line,
        "source_sha256": before,
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "binding_scope": "Python source inventory only; dependencies and non-Python files are not bound",
        "source_unchanged": stable,
        "observer_integrity": "IN_PROCESS_NOT_ATTESTED",
        "baseline": baseline,
        "challenge": challenge,
        "limits": [
            "Local supervised execution; no isolation or independent accuracy claim",
            "Trusted project code only; hostile code can alter the in-process observer",
            "No automatic finding suppression, approval or release authority",
        ],
    }
    if kind == "call":
        result.update(
            {
                "call_scope": qualname,
                "execution_point": "Before the selected call statement; reachability and injected failure escape only",
                "production_function_mutation_sensitivity": "NOT_TESTED",
                "semantic_quality": "NOT_ASSESSED",
            }
        )
        result["limits"].insert(
            2,
            "The injected failure tests statement reachability and failure escape, not production behavior",
        )
    else:
        result["assertion_qualname"] = qualname
        result["semantic_strength"] = "NOT_ASSESSED"
        result["limits"].insert(
            2, "Reachability and propagation only; semantic strength is not proved"
        )
    return result


def _propagation_probe(root, nodeid, line, timeout, kind):
    if type(timeout) not in (int, float) or not 0 < timeout <= 300:
        raise ValueError("timeout must be between 0 and 300 seconds")
    root, path, qualname, manifest, before, config = _propagation_probe_inputs(
        root, nodeid, line, kind
    )
    pair = _propagation_probe_phases(
        root, path, nodeid, manifest, before, config, timeout
    )
    return _propagation_probe_result(
        kind, nodeid, line, before, qualname, pair, root, path, manifest
    )


def probe_assertion_propagation(root, nodeid, line, *, timeout=30):
    """Execute one test twice to observe assertion reachability and failure escape.

    Explicit local execution, not a sandbox, semantic-oracle proof, independent
    accuracy measurement or authority to clear a scanner finding. Constant and
    otherwise weak assertions can propagate too; callers must assess their intent.
    """
    return _propagation_probe(root, nodeid, line, timeout, "assertion")


def probe_call_propagation(root, nodeid, line, *, timeout=30):
    """Inject before one standalone call to observe execution-point failure escape.

    This does not measure mutation sensitivity of the production function, semantic
    quality, or whether a scanner finding should be cleared. Project code runs locally.
    """
    return _propagation_probe(root, nodeid, line, timeout, "call")


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
        "source_manifest": _challenge_source_inventory(root),
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


def _typecheck_inputs(
    root,
    nodeid,
    signature_line,
    transfer_line,
    config_path,
    signature_kind=None,
    parameter_name=None,
):
    _typecheck_validate_lines(signature_line, transfer_line, config_path)
    root, source = _challenge_path(root, nodeid)
    if len(nodeid.split("::")) != 2:
        raise ValueError("Select one top-level test function")
    config = _typecheck_config_path(root, config_path)
    source_bytes = _typecheck_read_file(source, 4 * 1024 * 1024)
    config_bytes = _typecheck_read_file(config, 1024 * 1024)
    source_text, source_encoding = _typecheck_decode_source(source_bytes)
    tree = ast.parse(source_text)
    test, callbacks = _typecheck_test_callbacks(tree, nodeid)
    ignored_sites = _typecheck_scoped_suppressions(
        source_text, tree, test, source.relative_to(root).as_posix()
    )
    candidates = _typecheck_transfers(test, callbacks, transfer_line)
    if len(candidates) != 1:
        raise ValueError("Transfer line must identify one direct nested callback")
    callback, transfer_kind = candidates[0]
    if not _typecheck_decorator_supported(tree, callback):
        raise ValueError("Decorated callbacks are not supported")
    annotation, selected_kind, selected_name = _typecheck_signature(
        callback, signature_line, signature_kind, parameter_name
    )
    mutation_type = "object" if selected_kind == "return" else "int"
    if _typecheck_builtin_shadowed(tree):
        raise ValueError("Mutation built-in name is shadowed in the source")
    mutated = _typecheck_mutated_source(
        source_text, source_encoding, annotation, mutation_type
    )
    expected_code = "arg-type" if transfer_kind == "call" else "dict-item"
    _typecheck_config_safe(config, config_bytes)
    return (
        root,
        source,
        config,
        source_bytes,
        mutated,
        expected_code,
        mutation_type,
        selected_kind,
        selected_name,
        ignored_sites,
    )


def _typecheck_validate_lines(signature_line, transfer_line, config_path):
    if (
        type(signature_line) is not int
        or type(transfer_line) is not int
        or not isinstance(config_path, str)
        or not config_path
    ):
        raise ValueError("Typecheck lines and config path are required")
    if signature_line == transfer_line or min(signature_line, transfer_line) < 1:
        raise ValueError("Signature and transfer lines must be distinct")


def _typecheck_config_path(root, config_path):
    relative = Path(config_path)
    if relative.is_absolute():
        raise ValueError("Checker config must be a relative project path")
    config = root / relative
    if (
        _typecheck_path_chain_linked(config)
        or not config.resolve().is_relative_to(root)
        or not config.is_file()
    ):
        raise ValueError("Checker config must be a regular in-project file")

    return config.resolve()


def _typecheck_test_callbacks(tree, nodeid):
    test_name = nodeid.split("::", 1)[1]
    tests = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == test_name
    ]
    if len(tests) != 1 or not test_name.startswith("test_"):
        raise ValueError("Selected node ID must name one top-level test function")
    test = tests[0]
    callbacks = [
        node
        for node in test.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    callbacks.extend(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node is not test
        and not node.name.startswith("test_")
    )
    return test, callbacks


def _typecheck_signature(callback, signature_line, signature_kind, parameter_name):
    _typecheck_signature_selector_valid(signature_kind, parameter_name)
    annotations = _typecheck_parameter_annotations(
        callback, signature_line, signature_kind, parameter_name
    )
    annotations.extend(
        _typecheck_signature_variadic(
            callback, signature_line, signature_kind, parameter_name
        )
    )
    if callback.returns is not None and callback.returns.lineno == signature_line:
        if signature_kind in (None, "return") and parameter_name is None:
            annotations.append((callback.returns, "return", None))
    if len(annotations) != 1:
        raise ValueError("Signature selectors must identify one direct annotation")
    annotation, kind, name = annotations[0]
    if annotation.lineno != annotation.end_lineno:
        raise ValueError("Multiline signature annotations are not supported")
    return annotation, kind, name


def _typecheck_parameter_annotations(callback, line, kind, name):
    return [
        (argument.annotation, "parameter", argument.arg)
        for argument in _typecheck_signature_arguments(callback)
        if _typecheck_parameter_annotation_matches(argument, line, kind, name)
    ]


def _typecheck_parameter_annotation_matches(argument, line, kind, name):
    return (
        argument.annotation is not None
        and argument.annotation.lineno == line
        and kind in (None, "parameter")
        and (name is None or argument.arg == name)
    )


def _typecheck_signature_selector_valid(signature_kind, parameter_name):
    if signature_kind not in (None, "parameter", "return"):
        raise ValueError("Signature kind must be parameter or return")
    if parameter_name is not None and (
        signature_kind != "parameter"
        or not isinstance(parameter_name, str)
        or not parameter_name.isidentifier()
    ):
        raise ValueError("Parameter name requires parameter signature kind")


def _typecheck_signature_arguments(callback):
    return [*callback.args.posonlyargs, *callback.args.args, *callback.args.kwonlyargs]


def _typecheck_signature_variadic(callback, line, kind, name):
    rows = []
    for argument in (callback.args.vararg, callback.args.kwarg):
        if (
            argument is None
            or argument.annotation is None
            or argument.annotation.lineno != line
        ):
            continue
        if kind in (None, "parameter") and (name is None or argument.arg == name):
            rows.append((argument.annotation, "parameter", argument.arg))
    return rows


def _typecheck_decorator_supported(tree, callback):
    if not callback.decorator_list:
        return True
    if len(callback.decorator_list) != 1:
        return False
    decorator = callback.decorator_list[0]
    if not isinstance(decorator, ast.Name):
        return False
    alias = decorator.id
    imports = _typecheck_decorator_imports(tree, alias)
    bindings = _typecheck_decorator_bindings(tree, alias)
    stores = _typecheck_decorator_stores(tree, alias)
    return len(imports) == len(bindings) == 1 and not stores


def _typecheck_decorator_imports(tree, alias):
    return [
        item
        for statement in tree.body
        if isinstance(statement, ast.ImportFrom)
        and statement.level == 0
        and statement.module == "contextlib"
        for item in statement.names
        if item.name == "asynccontextmanager" and (item.asname or item.name) == alias
    ]


def _typecheck_decorator_bindings(tree, alias):
    return [
        item
        for statement in ast.walk(tree)
        if isinstance(statement, (ast.Import, ast.ImportFrom))
        for item in statement.names
        if (item.asname or item.name.split(".")[0]) == alias
    ]


def _typecheck_decorator_stores(tree, alias):
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == alias
        and isinstance(node.ctx, ast.Store)
    ]


def _typecheck_builtin_shadowed(tree):
    return any(_typecheck_builtin_binding(node) for node in ast.walk(tree))


def _typecheck_builtin_binding(node):
    builtins = {"int", "object"}
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
        return node.id in builtins
    if isinstance(node, ast.arg):
        return node.arg in builtins
    if isinstance(node, ast.ExceptHandler):
        return node.name in builtins
    if isinstance(node, (ast.MatchAs, ast.MatchStar)):
        return node.name in builtins
    if isinstance(node, ast.MatchMapping):
        return node.rest in builtins
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name in builtins
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return any(
            (alias.asname or alias.name.split(".")[0]) in builtins
            for alias in node.names
        )
    return False


def _typecheck_transfers(test, callbacks, line):
    callback_names = {callback.name: callback for callback in callbacks}
    if len(callback_names) != len(callbacks):
        return []
    transfers = []
    for node in ast.walk(test):
        transfers.extend(_typecheck_node_transfers(node, line, callback_names))
    if len(transfers) != 1:
        return []
    callback = transfers[0][0]

    if not _typecheck_transfer_references_valid(test, callback, line):
        return []
    return transfers


def _typecheck_node_transfers(node, line, callback_names):
    start, end = getattr(node, "lineno", None), getattr(node, "end_lineno", None)
    if start is None or end is None or not start <= line <= end:
        return []
    if isinstance(node, ast.Call):
        values = [*node.args, *(keyword.value for keyword in node.keywords)]
        transfer_kind = "call"
    elif isinstance(node, ast.Dict):
        values = node.values
        transfer_kind = "dict"
    else:
        return []
    matches = [
        callback_names[value.id]
        for value in values
        if isinstance(value, ast.Name) and value.id in callback_names
    ]
    return [(callback, transfer_kind) for callback in matches]


def _typecheck_transfer_references_valid(test, callback, line):
    refs = [
        node
        for node in ast.walk(test)
        if isinstance(node, ast.Name) and node.id == callback.name
    ]
    definition = [
        node
        for node in ast.walk(callback)
        if isinstance(node, ast.Name) and node.id == callback.name
    ]
    transfer_refs = [
        node
        for node in ast.walk(test)
        if isinstance(node, ast.Name)
        and node.id == callback.name
        and node.lineno <= line <= node.end_lineno
    ]
    return len(refs) == len(definition) + 1 and len(transfer_refs) == 1


def _typecheck_decode_source(payload):
    encoding, _ = tokenize.detect_encoding(io.BytesIO(payload).readline)
    return payload.decode(encoding), encoding


def _typecheck_source_suppressed(source):
    comments = tokenize.generate_tokens(io.StringIO(source).readline)
    return any(
        token.type == tokenize.COMMENT
        and ("type: ignore" in token.string.lower() or "mypy:" in token.string.lower())
        for token in comments
    )


def _typecheck_scoped_suppressions(source, tree, test, source_path):
    protected = set(range(test.lineno, test.end_lineno + 1))
    closure = _typecheck_test_name_closure(tree, test)
    unrelated_tests = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
        and node is not test
        and node.name not in closure
    ]
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            protected.update(range(node.lineno, node.end_lineno + 1))
    ignored = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        entry = _typecheck_suppression_entry(
            token, source, tree, protected, unrelated_tests, closure, source_path
        )
        if entry is not None:
            ignored.append(entry)
    return ignored


def _typecheck_suppression_entry(
    token, source, tree, protected, unrelated_tests, closure, source_path
):
    if token.type != tokenize.COMMENT:
        return None
    comment = token.string.lower()
    if "mypy:" in comment:
        raise ValueError("Module-level mypy directives are unsupported")
    if "type: ignore" not in comment:
        return None
    line = token.start[0]
    if line in protected or _typecheck_definition_header_line(source, tree, line):
        raise ValueError("Type ignore is inside selected test, import, or definition")
    reason = _typecheck_suppression_scope(tree, line, unrelated_tests, closure)
    return {
        "path": source_path,
        "line": line,
        "reason": reason,
        "comment_sha256": hashlib.sha256(token.string.encode("utf-8")).hexdigest(),
    }


def _typecheck_suppression_scope(tree, line, unrelated_tests, closure):
    if any(_typecheck_test_body_contains(node, line) for node in unrelated_tests):
        return "unreferenced_test_body"
    reason = _typecheck_unreferenced_assignment_reason(tree, line, closure)
    if reason is None:
        raise ValueError("Type ignore is outside a proven unrelated scope")
    return reason


def _typecheck_test_body_contains(node, line):
    return (
        bool(node.body)
        and line > node.lineno
        and min(statement.lineno for statement in node.body) <= line <= node.end_lineno
    )


def _typecheck_definition_header_line(source, tree, line):
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        starts = [node.lineno, *(item.lineno for item in node.decorator_list)]
        end = _typecheck_definition_colon(source, node)
        if end is None:
            raise ValueError("Definition header could not be bounded")
        if min(starts) <= line <= end:
            return True
    return False


def _typecheck_definition_colon(source, node):
    keyword = "class" if isinstance(node, ast.ClassDef) else "def"
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    started = False
    depth = 0
    for token in tokens:
        if not started:
            started = _typecheck_definition_token(token, node, keyword)
            continue
        if token.type != tokenize.OP:
            continue
        depth = _typecheck_token_depth(token, depth)
        if token.string == ":" and depth == 0:
            return token.start[0]
    return None


def _typecheck_definition_token(token, node, keyword):
    return (
        token.type == tokenize.NAME
        and token.string == keyword
        and token.start[0] == node.lineno
        and token.start[1] >= node.col_offset
    )


def _typecheck_token_depth(token, depth):
    return depth + (1 if token.string in "([{" else -1 if token.string in ")]}" else 0)


def _typecheck_test_name_closure(tree, test):
    names = {
        node.id
        for node in ast.walk(test)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }
    reflective = {"eval", "exec", "globals", "locals", "getattr", "__import__"}
    if names & reflective:
        raise ValueError("Selected test uses dynamic name lookup")
    changed = True
    while changed:
        changed = _typecheck_expand_module_bindings(tree, names)
    return names


def _typecheck_expand_module_bindings(tree, names):
    changed = False
    for statement in tree.body:
        if _typecheck_statement_names(statement) & names:
            loaded = {
                node.id
                for node in ast.walk(statement)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
            }
            if loaded & {"eval", "exec", "globals", "locals", "getattr", "__import__"}:
                raise ValueError("Selected test dependency uses dynamic name lookup")
            previous = len(names)
            names.update(loaded)
            changed |= len(names) != previous
    return changed


def _typecheck_statement_names(statement):
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {statement.name}
    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        return {
            alias.asname
            or (
                alias.name.split(".")[0]
                if isinstance(statement, ast.Import)
                else alias.name
            )
            for alias in statement.names
        }
    return {
        node.id
        for node in ast.walk(statement)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }


def _typecheck_unreferenced_assignment_reason(tree, line, closure):
    statements = [node for node in tree.body if node.lineno <= line <= node.end_lineno]
    if len(statements) != 1 or not isinstance(statements[0], ast.Assign):
        return None
    assignment = statements[0]
    if len(assignment.targets) != 1 or not isinstance(assignment.targets[0], ast.Name):
        return None
    if assignment.targets[0].id in closure:
        return None
    return "unreferenced_assignment"


def _typecheck_mutated_source(source, encoding, annotation, mutation_type):
    lines = source.splitlines(keepends=True)
    line = lines[annotation.lineno - 1]
    encoded = line.encode("utf-8")
    start, end = annotation.col_offset, annotation.end_col_offset
    if start < 0 or end <= start or end > len(encoded):
        raise ValueError("Signature annotation span is invalid")
    start_char = len(encoded[:start].decode("utf-8"))
    end_char = len(encoded[:end].decode("utf-8"))
    lines[annotation.lineno - 1] = line[:start_char] + mutation_type + line[end_char:]
    return "".join(lines).encode(encoding)


def _typecheck_read_file(path, limit):
    if _typecheck_path_chain_linked(path):
        raise ValueError("Probe inputs cannot contain linked ancestors")
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("Probe input exceeds its byte limit")
    return payload


def _typecheck_config_safe(path, payload):
    text = payload.decode("utf-8")
    if path.suffix.lower() == ".toml":
        from .review_audits import tomllib

        document = tomllib.loads(text)
        section = document.get("tool", {}).get("mypy")
        if not isinstance(section, dict):
            raise ValueError("Checker config must declare its mypy settings")
        overrides = section.get("overrides", [])
        if not isinstance(overrides, list):
            raise ValueError("Mypy overrides must be a list")
        value_sets = [section, *overrides]
    else:
        parser = configparser.ConfigParser()
        parser.read_string(text)
        sections = [
            name
            for name in parser.sections()
            if name.lower() == "mypy" or name.lower().startswith("mypy-")
        ]
        if not sections:
            raise ValueError("Checker config must declare its mypy settings")
        value_sets = [dict(parser.items(name)) for name in sections]
    if any(not isinstance(values, dict) for values in value_sets):
        raise ValueError("Mypy config sections and overrides must be mappings")
    lowered_sets = [
        {str(key).lower().replace("-", "_"): value for key, value in values.items()}
        for values in value_sets
    ]
    if any(_typecheck_config_suppresses(values) for values in lowered_sets):
        raise ValueError("Checker config contains a suppressed or executable option")
    if any(
        str(values.get("follow_imports", "normal")).lower() != "normal"
        for values in lowered_sets
    ):
        raise ValueError("Checker config must follow imports normally")
    if any(
        _typecheck_config_true(values.get("follow_imports_for_stubs", False))
        for values in lowered_sets
    ):
        raise ValueError("Checker config changes stub import following")


def _typecheck_config_suppresses(values):
    return (
        _typecheck_config_present(values.get("plugins", []))
        or _typecheck_config_true(values.get("ignore_errors", False))
        or _typecheck_config_true(values.get("ignore_missing_imports", False))
        or _typecheck_config_present(values.get("disable_error_code", []))
    )


def _typecheck_config_true(value):
    if isinstance(value, (list, tuple, dict, set)):
        return bool(value)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "yes", "1"}


def _typecheck_config_present(value):
    if isinstance(value, (list, tuple, dict, set)):
        return bool(value)
    return bool(str(value).strip())


def _typecheck_distribution_manifest():
    try:
        distribution = importlib.metadata.distribution("mypy")
    except importlib.metadata.PackageNotFoundError as error:
        raise ValueError("Mypy is not installed in this interpreter") from error
    files = distribution.files or ()
    if len(files) > 4096:
        raise ValueError("Mypy installation exceeds the file limit")
    paths = [Path(distribution.locate_file(item)) for item in files]
    rows = _typecheck_file_manifest(paths, 96 * 1024 * 1024)
    identity = {
        "version": distribution.version,
        "files": rows,
    }
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest(), distribution.version


def _typecheck_file_manifest(paths, byte_limit):
    if len(paths) > 4096:
        raise ValueError("Checker input set exceeds the file limit")
    rows, consumed = [], 0
    for path in sorted(set(paths), key=str):
        if path.is_symlink() or _typecheck_reparse(path) or not path.is_file():
            raise ValueError("Checker input is missing or linked")
        digest, size = _challenge_source_digest(path, byte_limit - consumed)
        consumed += size
        rows.append([str(path.resolve()), digest])
    return rows


def _typecheck_parsed_paths(output):
    return set(_typecheck_parsed_modules(output))


def _typecheck_parsed_modules(output):
    modules = {}
    for line in output.splitlines():
        match = re.match(r"^LOG:\s+Parsing\s+(.+?) \(([^()]+)\)$", line)
        if match:
            path, module = Path(match.group(1)), match.group(2)
            if path in modules and modules[path] != module:
                raise ValueError("Checker assigned conflicting module identities")
            modules[path] = module
    return modules


def _typecheck_diagnostics(output, source, root):
    errors = []
    pattern = re.compile(
        r"^(.*):(\d+): (?:error|fatal): .*?(?: \[([A-Za-z0-9_-]+)\])?$"
    )
    for line in output.splitlines():
        if " error:" not in line and " fatal:" not in line:
            continue
        match = pattern.match(line)
        if match is None:
            errors.append({"path": "UNKNOWN", "line": None, "code": "UNKNOWN"})
            continue
        path = Path(match.group(1))
        try:
            relative = path.resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            relative = "EXTERNAL"
        errors.append(
            {
                "path": relative,
                "line": int(match.group(2)),
                "code": match.group(3) or "UNKNOWN",
            }
        )
    return errors


def _typecheck_run(argv, root, timeout, environment, stdout_path, stderr_path):
    from .runtime_audit_process import _facts, _launch, _run_child_bounded

    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        started = time.monotonic()
        try:
            child = _launch(argv, root, environment)
        except OSError:
            return {
                "launch_error": True,
                "cleanup_confirmed": False,
                "timeout_seconds": float(timeout),
            }
        facts = _run_child_bounded(
            child,
            _facts(),
            max(1, math.ceil(timeout)),
            started + timeout,
            started,
            stdout,
            stderr,
            None,
        )
        facts["timeout_seconds"] = float(timeout)
        return facts


def _typecheck_output(paths, limit=8 * 1024 * 1024):
    output = []
    for path in paths:
        try:
            payload = _typecheck_read_file(path, limit)
            output.append(payload.decode("utf-8"))
        except (OSError, UnicodeError, ValueError):
            return None
    return "\n".join(output)


def _typecheck_argv(root, source, config, shadow, cache):
    return [
        sys.executable,
        "-I",
        "-m",
        "mypy",
        "--config-file",
        str(config),
        "--strict",
        "--no-incremental",
        "--no-color-output",
        "--show-absolute-path",
        "--show-error-codes",
        "--no-error-summary",
        "--follow-imports=normal",
        "--cache-dir",
        str(cache),
        "--shadow-file",
        str(source),
        str(shadow),
        "-v",
        str(source),
    ]


def _typecheck_search_path_command(source, config, shadow, cache):
    options = [
        "--config-file",
        str(config),
        "--strict",
        "--no-incremental",
        "--no-color-output",
        "--show-absolute-path",
        "--show-error-codes",
        "--no-error-summary",
        "--follow-imports=normal",
        "--cache-dir",
        str(cache),
        "--shadow-file",
        str(source),
        str(shadow),
        str(source),
    ]
    script = (
        "import io,json,sys; "
        "from mypy.main import process_options; "
        "from mypy.modulefinder import compute_search_paths; "
        "from mypy.build import default_data_dir; "
        "args=json.loads(sys.argv[1]); "
        "sources,options=process_options(args,stdout=io.StringIO(),stderr=io.StringIO()); "
        "paths=compute_search_paths(sources,options,default_data_dir()); "
        "print(json.dumps({name:list(getattr(paths,name)) for name in "
        "('python_path','mypy_path','package_path','typeshed_path')}))"
    )
    return [sys.executable, "-I", "-c", script, json.dumps(options)]


def _typecheck_search_paths(
    root, source, config, shadow, cache, timeout, environment, scratch, label
):
    stdout_path = scratch / f"{label}-paths.stdout"
    stderr_path = scratch / f"{label}-paths.stderr"
    facts = _typecheck_run(
        _typecheck_search_path_command(source, config, shadow, cache),
        root,
        timeout,
        environment,
        stdout_path,
        stderr_path,
    )
    output = _typecheck_output([stdout_path, stderr_path])
    if not _typecheck_run_valid(facts, output):
        return None, facts
    try:
        paths = json.loads(output)
    except json.JSONDecodeError:
        return None, facts
    expected = {"python_path", "mypy_path", "package_path", "typeshed_path"}
    if (
        not isinstance(paths, dict)
        or set(paths) != expected
        or any(
            not isinstance(values, list)
            or any(not isinstance(value, str) or not value for value in values)
            for values in paths.values()
        )
    ):
        return None, facts
    normalized = {
        name: [str(_typecheck_resolver_path(value)) for value in values]
        for name, values in paths.items()
    }
    return normalized, facts


def _typecheck_resolver_path(value):
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("Checker search path must be absolute")
    if _typecheck_path_chain_linked(path):
        raise ValueError("Checker search path contains a linked ancestor")
    return path.resolve()


def _typecheck_path_chain_linked(path):
    current = Path(path).absolute()
    for _ in range(64):
        try:
            info = current.lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ValueError("Path ancestry could not be validated") from error
        else:
            if current.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                return True
        parent = current.parent
        if parent == current:
            return False
        current = parent
    raise ValueError("Path ancestry exceeds the validation limit")


def _typecheck_phase(root, source, config, shadow, cache, timeout, environment, label):
    argv = _typecheck_argv(root, source, config, shadow, cache)
    scratch = Path(environment["TMPDIR"])
    facts = _typecheck_run(
        argv,
        root,
        timeout,
        environment,
        scratch / f"{label}.stdout",
        scratch / f"{label}.stderr",
    )
    output = _typecheck_output(
        [scratch / f"{label}.stdout", scratch / f"{label}.stderr"]
    )
    return {
        "process": facts,
        "output": output,
        "modules": _typecheck_parsed_modules(output) if output is not None else {},
        "paths": set(_typecheck_parsed_modules(output))
        if output is not None
        else set(),
        "diagnostics": _typecheck_diagnostics(output, source, root)
        if output is not None
        else [{"path": "UNKNOWN", "line": None, "code": "OUTPUT_LIMIT"}],
    }


def _typecheck_input_manifest(phase):
    paths = phase["paths"]
    try:
        rows = _typecheck_dependency_manifest(paths, 128 * 1024 * 1024)
    except (OSError, ValueError):
        return None
    return rows if rows else None


def _typecheck_dependency_manifest(paths, byte_limit):
    if len(paths) > 4096:
        raise ValueError("Type dependency inventory exceeds the file limit")
    source_rows, consumed = _typecheck_dependency_source_rows(paths, byte_limit)
    marker_paths = _typecheck_marker_paths(paths)
    marker_rows, _consumed = _typecheck_marker_rows(marker_paths, byte_limit, consumed)
    return sorted([*source_rows, *marker_rows], key=lambda row: row[0])


def _typecheck_dependency_source_rows(paths, byte_limit):
    source_rows, consumed, entries = [], 0, 0
    for path in sorted(set(paths), key=str):
        if _typecheck_path_chain_linked(path):
            raise ValueError("Type dependency is missing or linked")
        if path.is_file():
            digest, size = _challenge_source_digest(path, byte_limit - consumed)
            consumed += size
        elif path.is_dir():
            row, consumed, entries = _typecheck_dependency_directory_row(
                path, byte_limit, consumed, entries
            )
            source_rows.append(row)
            continue
        else:
            raise ValueError("Type dependency is missing or unsupported")
        source_rows.append([str(path.resolve()), digest])
    return source_rows, consumed


def _typecheck_dependency_directory_row(path, byte_limit, consumed, entries):
    inventory, budget = [], {"entries": entries, "bytes": consumed, "limit": byte_limit}
    _typecheck_inventory_tree(path, path.parent, inventory, budget, 0)
    payload = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    row = [str(path.resolve()), hashlib.sha256(payload).hexdigest()]
    return row, budget["bytes"], budget["entries"]


def _typecheck_marker_paths(paths):
    marker_paths = set()
    for path in paths:
        if _typecheck_path_chain_linked(path):
            raise ValueError("Type dependency path contains a linked ancestor")
        current = path.resolve() if path.is_dir() else path.resolve().parent
        for _ in range(32):
            marker_paths.add(current / "py.typed")
            if current.name.lower() in {"site-packages", "dist-packages"}:
                break
            parent = current.parent
            if parent == current:
                break
            current = parent
        else:
            raise ValueError("Type dependency path exceeds ancestor limit")
    if len(marker_paths) > 8192:
        raise ValueError("Type dependency inventory exceeds the file limit")

    return marker_paths


def _typecheck_marker_rows(marker_paths, byte_limit, consumed):
    rows = []
    for marker in sorted(marker_paths, key=str):
        if marker.is_symlink() or _typecheck_reparse(marker):
            raise ValueError("Type dependency marker is linked")
        if not marker.exists():
            rows.append([str(marker), "MISSING"])
            continue
        digest, size = _challenge_source_digest(marker, byte_limit - consumed)
        consumed += size
        rows.append([str(marker.resolve()), digest])
    return rows, consumed


def _typecheck_import_names(phase, target_source):
    modules = phase["modules"]
    if not modules or any(not path.is_file() and not path.is_dir() for path in modules):
        raise ValueError("Checker import graph is incomplete")
    names = set()
    for path, module_id in modules.items():
        names.update(_typecheck_module_prefixes(module_id))
        if path.is_file():
            names.update(
                _typecheck_import_names_from_file(path, module_id, target_source)
            )
    if not names:
        raise ValueError("Checker import graph has no resolvable module names")
    return names


def _typecheck_import_names_from_file(path, module_id, target_source):
    payload = _typecheck_read_file(path, 4 * 1024 * 1024)
    source, _encoding = _typecheck_decode_source(payload)
    tree = ast.parse(source)
    if not _typecheck_checker_input_allowed(path, target_source):
        _typecheck_dependency_suppression_sites(source, tree, path, module_id, payload)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.update(_typecheck_module_prefixes(alias.name))
        elif isinstance(node, ast.ImportFrom):
            names.update(_typecheck_from_import_names(node, module_id, path))
    return names


def _typecheck_dependency_suppression_sites(
    source, tree, path, module_id, source_bytes
):
    sites = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type != tokenize.COMMENT:
            continue
        comment = token.string.lower()
        if "mypy:" in comment:
            raise ValueError("Parsed dependency contains a mypy directive")
        if "type: ignore" not in comment:
            continue
        statement, function = _typecheck_dependency_ignore_nodes(tree, token.start[0])
        segment = "\n".join(
            source.splitlines()[statement.lineno - 1 : statement.end_lineno]
        )
        digest = hashlib.sha256(segment.encode("utf-8")).hexdigest()
        sites.append(
            {
                "path": _typecheck_external_path(path),
                "module": module_id,
                "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
                "line": token.start[0],
                "comment_sha256": hashlib.sha256(
                    token.string.encode("utf-8")
                ).hexdigest(),
                "statement_sha256": digest,
            }
        )
    return sites


def _typecheck_dependency_ignore_nodes(tree, line):
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    comments = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and node.lineno <= line <= node.end_lineno
        and _typecheck_simple_local_target(node)
    ]
    if len(comments) != 1:
        raise ValueError("Dependency type ignore is not a simple local assignment")
    statement = comments[0]
    function = _typecheck_enclosing_function(statement, parents)
    if function is None or not _typecheck_dependency_function_safe(function, parents):
        raise ValueError("Dependency type ignore affects an unsupported contract")
    return statement, function


def _typecheck_simple_local_target(statement):
    targets = (
        statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    )
    return len(targets) == 1 and isinstance(targets[0], ast.Name)


def _typecheck_enclosing_function(statement, parents):
    current = parents.get(statement)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        if isinstance(current, ast.ClassDef):
            return None
        current = parents.get(current)
    return None


def _typecheck_dependency_function_safe(function, parents):
    parent = parents.get(function)
    is_method = isinstance(parent, ast.ClassDef)
    assigned = _typecheck_assignment_names(function)
    return (
        _typecheck_dependency_assignments_safe(function, assigned)
        and _typecheck_dependency_signature_safe(function, is_method)
        and _typecheck_dependency_scope_safe(function, parent, parents)
    )


def _typecheck_dependency_assignments_safe(function, assigned):
    return not any(
        isinstance(node, (ast.Global, ast.Nonlocal))
        and any(name in assigned for name in node.names)
        for node in ast.walk(function)
    )


def _typecheck_dependency_signature_safe(function, is_method):
    return (
        isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not function.decorator_list
        and function.returns is not None
        and _typecheck_dependency_arguments_annotated(function, is_method)
        and (
            function.args.vararg is None or function.args.vararg.annotation is not None
        )
        and (function.args.kwarg is None or function.args.kwarg.annotation is not None)
        and not any(
            isinstance(node, (ast.Yield, ast.YieldFrom)) for node in ast.walk(function)
        )
    )


def _typecheck_dependency_scope_safe(function, parent, parents):
    current = parent
    if isinstance(current, ast.ClassDef):
        if function not in current.body:
            return False
        current = parents.get(current)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return False
        current = parents.get(current)
    return True


def _typecheck_dependency_arguments_annotated(function, is_method):
    for index, argument in enumerate(_typecheck_signature_arguments(function)):
        if argument.annotation is None and not (
            is_method and index == 0 and argument.arg in {"self", "cls"}
        ):
            return False
    return True


def _typecheck_assignment_names(function):
    return {
        target.id
        for node in ast.walk(function)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
        if isinstance(target, ast.Name)
    }


def _typecheck_external_path(path):
    for parent in path.parents:
        if parent.name.lower() in {"site-packages", "dist-packages"}:
            return path.relative_to(parent).as_posix()
    raise ValueError("Dependency suppression has no bounded package-relative path")


def _typecheck_checker_input_allowed(path, target_source):
    return (
        path.resolve() == target_source.resolve()
        or _typecheck_is_checker_typeshed(path)
        or _typecheck_is_pytest_bundle(path)
    )


def _typecheck_is_pytest_bundle(path):
    distributions = importlib.metadata.packages_distributions()
    if "pytest" not in distributions.get(path.parts[-2].lower(), []):
        return False
    distribution = importlib.metadata.distribution("pytest")
    pytest_root = Path(distribution.locate_file("_pytest")).resolve()
    return path.resolve().is_relative_to(pytest_root.parent)


def _typecheck_is_checker_typeshed(path):
    distribution = importlib.metadata.distribution("mypy")
    typeshed = Path(distribution.locate_file("mypy/typeshed")).resolve()
    return path.resolve().is_relative_to(typeshed)


def _typecheck_from_import_names(node, module_id, path):
    name = node.module or ""
    if node.level:
        package = (
            module_id
            if path.name.startswith("__init__.")
            else module_id.rpartition(".")[0]
        )
        name = importlib.util.resolve_name("." * node.level + name, package)
    names = _typecheck_module_prefixes(name)
    for alias in node.names:
        if alias.name != "*":
            target = ".".join(filter(None, (name, alias.name)))
            names.update(_typecheck_module_prefixes(target))
    return names


def _typecheck_module_prefixes(name):
    parts = name.split(".") if name else []
    if not parts or any(not part.isidentifier() for part in parts):
        raise ValueError("Checker import name is not statically resolvable")
    return {".".join(parts[:index]) for index in range(1, len(parts) + 1)}


def _typecheck_resolver_manifest(
    search_paths, module_names, byte_limit=128 * 1024 * 1024
):
    if sum(len(search_paths[name]) for name in search_paths) > 256:
        raise ValueError("Checker search path exceeds the root limit")
    rows, budget = [], {"entries": 0, "bytes": 0, "limit": byte_limit}
    for category in ("python_path", "mypy_path", "package_path", "typeshed_path"):
        for root in search_paths[category]:
            _typecheck_resolver_root(
                category, Path(root), module_names, rows, budget, byte_limit
            )
    rows.sort(key=lambda row: tuple(str(value) for value in row))
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest(), budget["entries"], budget["bytes"]


def _typecheck_resolver_root(category, root_path, module_names, rows, budget, limit):
    rows.append([category, str(root_path), _typecheck_path_kind(root_path)])
    if root_path.is_dir():
        for top in sorted({name.split(".", 1)[0] for name in module_names}):
            subtree_rows = []
            _typecheck_resolver_package(root_path, top, subtree_rows, budget)
            rows.extend([[category, str(root_path), *row] for row in subtree_rows])
    elif root_path.is_file():
        digest, size = _challenge_source_digest(root_path, limit - budget["bytes"])
        budget["bytes"] += size
        rows.append([category, str(root_path), "FILE", digest])
    elif root_path.exists():
        raise ValueError("Checker search root has unsupported type")


def _typecheck_resolver_package(root_path, top, rows, budget):
    for suffix in ("", "-stubs"):
        _typecheck_inventory_candidate(root_path / f"{top}{suffix}", rows, budget)
    for extension in (".py", ".pyi", "-stubs.py", "-stubs.pyi"):
        candidate = root_path / f"{top}{extension}"
        if candidate.exists():
            _typecheck_inventory_entry(candidate, root_path, rows, budget)
        else:
            _typecheck_inventory_missing(candidate, root_path, rows, budget)


def _typecheck_path_kind(path):
    if path.is_symlink() or _typecheck_reparse(path):
        raise ValueError("Checker resolver path is linked")
    if not path.exists():
        return "MISSING"
    if path.is_dir():
        return "DIRECTORY"
    if path.is_file():
        return "FILE"
    raise ValueError("Checker resolver path type is unsupported")


def _typecheck_reparse(path):
    try:
        attributes = getattr(path.stat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(
        attributes & getattr(__import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _typecheck_inventory_candidate(path, rows, budget):
    if path.is_symlink():
        raise ValueError("Checker package subtree contains a link")
    if not path.exists():
        _typecheck_inventory_missing(path, path.parent, rows, budget)
    elif _typecheck_reparse(path):
        raise ValueError("Checker package subtree contains a link")
    elif path.is_dir():
        _typecheck_inventory_tree(path, path.parent, rows, budget, 0)
    elif path.is_file():
        _typecheck_inventory_entry(path, path.parent, rows, budget)
    else:
        raise ValueError("Checker package candidate has unsupported type")


def _typecheck_inventory_tree(path, base, rows, budget, depth):
    if depth > 32:
        raise ValueError("Checker package subtree exceeds its depth limit")
    _typecheck_inventory_add(rows, budget, [str(path.relative_to(base)), "DIRECTORY"])
    with os.scandir(path) as entries:
        remaining = 8192 - budget["entries"]
        children = []
        for entry in entries:
            children.append(entry)
            if len(children) > remaining:
                raise ValueError("Checker resolver inventory exceeds the entry limit")
        children.sort(key=lambda entry: entry.name)
    for entry in children:
        child = Path(entry.path)
        if entry.is_symlink() or _typecheck_reparse(child):
            raise ValueError("Checker package subtree contains a link")
        if entry.is_dir(follow_symlinks=False):
            _typecheck_inventory_tree(child, base, rows, budget, depth + 1)
        elif entry.is_file(follow_symlinks=False):
            _typecheck_inventory_entry(child, base, rows, budget)
        else:
            raise ValueError("Checker package subtree entry has unsupported type")


def _typecheck_inventory_entry(path, base, rows, budget):
    if path.is_symlink() or _typecheck_reparse(path):
        raise ValueError("Checker package subtree contains a link")
    relative = str(path.relative_to(base))
    suffix = path.name.lower()
    row = [relative, "FILE"]
    if suffix.endswith((".py", ".pyi")) or suffix == "py.typed":
        digest, size = _challenge_source_digest(path, budget["limit"] - budget["bytes"])
        budget["bytes"] += size
        row.append(digest)
    _typecheck_inventory_add(rows, budget, row)


def _typecheck_inventory_missing(path, base, rows, budget):
    _typecheck_inventory_add(rows, budget, [str(path.relative_to(base)), "MISSING"])


def _typecheck_inventory_add(rows, budget, row):
    budget["entries"] += 1
    if budget["entries"] > 8192:
        raise ValueError("Checker resolver inventory exceeds the entry limit")
    rows.append(row)


def _typecheck_phase_clean(phase):
    return (
        _typecheck_run_valid(phase["process"], phase["output"])
        and not phase["diagnostics"]
    )


def _typecheck_transfer_matches(phase, root, source, line, code):
    return _typecheck_run_valid(phase["process"], phase["output"], 1) and phase[
        "diagnostics"
    ] == [
        {
            "path": source.relative_to(root).as_posix(),
            "line": line,
            "code": code,
        }
    ]


def _typecheck_phase_report(phase):
    return {"process": phase["process"], "diagnostics": phase["diagnostics"]}


def _typecheck_python_identity():
    executable = Path(sys.executable).resolve(strict=True)
    digest, _ = _challenge_source_digest(executable, 128 * 1024 * 1024)
    identity = {
        "implementation": sys.implementation.name,
        "version": sys.version,
        "executable_path_sha256": hashlib.sha256(str(executable).encode()).hexdigest(),
        "executable_sha256": digest,
    }
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _typecheck_discovery_phase(
    root, source, config, shadow, cache, timeout, environment, scratch
):
    paths_before, facts_before = _typecheck_search_paths(
        root,
        source,
        config,
        shadow,
        cache,
        timeout,
        environment,
        scratch,
        "discovery-before",
    )
    phase = _typecheck_phase(
        root, source, config, shadow, cache, timeout, environment, "discovery"
    )
    manifest = _typecheck_input_manifest(phase)
    package, _ = _typecheck_distribution_manifest()
    paths_after, facts_after = _typecheck_search_paths(
        root,
        source,
        config,
        shadow,
        cache,
        timeout,
        environment,
        scratch,
        "discovery-after",
    )
    resolver = _typecheck_resolver_state(paths_after, phase, source)
    stable = (
        paths_before is not None
        and paths_before == paths_after
        and resolver is not None
    )
    return {
        "phase": phase,
        "manifest": manifest,
        "package": package,
        "paths_after": paths_after,
        "facts_before": facts_before,
        "facts_after": facts_after,
        "resolver": resolver,
        "stable": stable,
    }


def _typecheck_baseline_phase(
    root, source, config, shadow, cache, timeout, environment, scratch, discovery
):
    baseline = {}
    before = after = package_before = package_after = paths_before = paths_after = (
        resolver_before
    ) = resolver = None
    if (
        _typecheck_phase_clean(discovery["phase"])
        and discovery["manifest"]
        and discovery["stable"]
    ):
        paths_before, _ = _typecheck_search_paths(
            root,
            source,
            config,
            shadow,
            cache,
            timeout,
            environment,
            scratch,
            "baseline-before",
        )
        resolver_before = _typecheck_resolver_state(
            paths_before, discovery["phase"], source
        )
        before = _typecheck_input_manifest(discovery["phase"])
        package_before, _ = _typecheck_distribution_manifest()
        if (
            paths_before == discovery["paths_after"]
            and resolver_before == discovery["resolver"]
        ):
            baseline = _typecheck_phase(
                root, source, config, shadow, cache, timeout, environment, "baseline"
            )
            after = _typecheck_input_manifest(baseline)
            paths_after, _ = _typecheck_search_paths(
                root,
                source,
                config,
                shadow,
                cache,
                timeout,
                environment,
                scratch,
                "baseline-after",
            )
            resolver = _typecheck_resolver_state(paths_after, baseline, source)
            package_after, _ = _typecheck_distribution_manifest()
    clean = _typecheck_baseline_clean(
        baseline,
        before,
        after,
        package_before,
        package_after,
        paths_before,
        paths_after,
        resolver_before,
        resolver,
        discovery,
    )
    return {
        "phase": baseline,
        "before": before,
        "after": after,
        "package_before": package_before,
        "package_after": package_after,
        "paths_before": paths_before,
        "paths_after": paths_after,
        "resolver_before": resolver_before,
        "resolver": resolver,
        "clean": clean,
    }


def _typecheck_baseline_clean(
    phase,
    before,
    after,
    package_before,
    package_after,
    paths_before,
    paths_after,
    resolver_before,
    resolver,
    discovery,
):
    return (
        bool(phase)
        and _typecheck_phase_clean(phase)
        and before == discovery["manifest"] == after
        and discovery["package"] == package_before == package_after
        and paths_before == discovery["paths_after"] == paths_after
        and resolver_before == discovery["resolver"] == resolver
    )


def _typecheck_challenge_phase(
    root,
    source,
    config,
    shadow,
    cache,
    timeout,
    environment,
    scratch,
    baseline,
    mutated,
):
    challenge = {}
    before = after = package_before = package_after = paths_before = paths_after = (
        resolver_before
    ) = resolver = None
    if baseline["clean"]:
        paths_before, _ = _typecheck_search_paths(
            root,
            source,
            config,
            shadow,
            cache,
            timeout,
            environment,
            scratch,
            "challenge-before",
        )
        resolver_before = _typecheck_resolver_state(
            paths_before, baseline["phase"], source
        )
        before = _typecheck_input_manifest(baseline["phase"])
        package_before, _ = _typecheck_distribution_manifest()
        if (
            paths_before == baseline["paths_after"]
            and resolver_before == baseline["resolver"]
        ):
            shadow.write_bytes(mutated)
            challenge = _typecheck_phase(
                root, source, config, shadow, cache, timeout, environment, "challenge"
            )
            after = _typecheck_input_manifest(challenge)
            paths_after, _ = _typecheck_search_paths(
                root,
                source,
                config,
                shadow,
                cache,
                timeout,
                environment,
                scratch,
                "challenge-after",
            )
            resolver = _typecheck_resolver_state(paths_after, challenge, source)
            package_after, _ = _typecheck_distribution_manifest()
    return {
        "phase": challenge,
        "before": before,
        "after": after,
        "package_before": package_before,
        "package_after": package_after,
        "paths_before": paths_before,
        "paths_after": paths_after,
        "resolver_before": resolver_before,
        "resolver": resolver,
    }


def _typecheck_run_phases(root, source, config, original, mutated, timeout):
    from .runtime_audit_process import _environment

    with tempfile.TemporaryDirectory(prefix="cf-typecheck-probe-") as directory:
        path = _runner_temp_root(directory)
        shadow, cache = path / source.name, path / "cache"
        shadow.write_bytes(original)
        environment = _environment(path)
        environment["PYTHONIOENCODING"] = "utf-8"
        environment_sha = hashlib.sha256(
            json.dumps(sorted(environment.items()), separators=(",", ":")).encode()
        ).hexdigest()
        discovery = _typecheck_discovery_phase(
            root, source, config, shadow, cache, timeout, environment, path
        )
        baseline = _typecheck_baseline_phase(
            root, source, config, shadow, cache, timeout, environment, path, discovery
        )
        challenge = _typecheck_challenge_phase(
            root,
            source,
            config,
            shadow,
            cache,
            timeout,
            environment,
            path,
            baseline,
            mutated,
        )
        stable = (
            discovery["stable"]
            and baseline["paths_before"]
            == discovery["paths_after"]
            == baseline["paths_after"]
            and baseline["resolver_before"]
            == discovery["resolver"]
            == baseline["resolver"]
            and challenge["paths_before"]
            == baseline["paths_after"]
            == challenge["paths_after"]
            and challenge["resolver_before"]
            == baseline["resolver"]
            == challenge["resolver"]
        )
        return _typecheck_phase_evidence(
            discovery, baseline, challenge, stable, environment_sha
        )


def _typecheck_phase_evidence(discovery, baseline, challenge, stable, environment_sha):
    resolver, paths = discovery["resolver"], discovery["paths_after"]
    return {
        "discovery": discovery["phase"],
        "discovered_manifest": discovery["manifest"],
        "baseline": baseline["phase"],
        "baseline_before": baseline["before"],
        "baseline_after": baseline["after"],
        "baseline_clean": baseline["clean"],
        "discovery_package": discovery["package"],
        "baseline_package_before": baseline["package_before"],
        "baseline_package_after": baseline["package_after"],
        "challenge": challenge["phase"],
        "challenge_before": challenge["before"],
        "challenge_after": challenge["after"],
        "challenge_package_before": challenge["package_before"],
        "challenge_package_after": challenge["package_after"],
        "resolver_stable": stable,
        "resolver_manifest_sha256": resolver[0] if resolver else None,
        "resolver_entries": resolver[1] if resolver else None,
        "resolver_bytes": resolver[2] if resolver else None,
        "dependency_suppressions": resolver[3] if resolver else [],
        "search_paths_sha256": hashlib.sha256(
            json.dumps(paths, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if paths
        else None,
        "search_path_discovery": {
            "before": discovery["facts_before"],
            "after": discovery["facts_after"],
        },
        "environment_sha256": environment_sha,
    }


def _typecheck_resolver_state(search_paths, phase, target_source):
    if search_paths is None or not phase["modules"]:
        return None
    try:
        suppressions = _typecheck_dependency_suppressions(phase, target_source)
        names = _typecheck_import_names(phase, target_source)
        digest, entries, consumed = _typecheck_resolver_manifest(search_paths, names)
    except (OSError, SyntaxError, UnicodeError, ValueError):
        return None
    identity = hashlib.sha256(
        json.dumps(
            {
                "search_paths": search_paths,
                "module_names": sorted(names),
                "inventory": digest,
                "dependency_suppressions": suppressions,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return identity, entries, consumed, suppressions


def _typecheck_dependency_suppressions(phase, target_source):
    sites = []
    for path, module_id in phase["modules"].items():
        if (
            not path.is_file()
            or path.resolve() == target_source.resolve()
            or _typecheck_checker_input_allowed(path, target_source)
        ):
            continue
        payload = _typecheck_read_file(path, 4 * 1024 * 1024)
        source, _encoding = _typecheck_decode_source(payload)
        tree = ast.parse(source)
        sites.extend(
            _typecheck_dependency_suppression_sites(
                source, tree, path, module_id, payload
            )
        )
    return sorted(sites, key=lambda site: (site["module"], site["line"]))


def _typecheck_inputs_stable(source, root, evidence, package_sha):
    return (
        bool(evidence["challenge"])
        and source.resolve() in evidence["discovery"]["paths"]
        and source.resolve() in evidence["challenge"]["paths"]
        and evidence["discovered_manifest"] is not None
        and evidence["discovered_manifest"]
        == evidence["baseline_before"]
        == evidence["baseline_after"]
        and evidence["challenge_before"]
        == evidence["discovered_manifest"]
        == evidence["challenge_after"]
        and evidence["resolver_stable"]
        and evidence["discovery_package"]
        == evidence["baseline_package_before"]
        == evidence["baseline_package_after"]
        == evidence["challenge_package_before"]
        == evidence["challenge_package_after"]
        == package_sha
    )


def probe_typecheck_transfer(
    root,
    nodeid,
    signature_line,
    transfer_line,
    checker_config,
    *,
    timeout=60,
    signature_kind=None,
    parameter_name=None,
):
    """Mutate one callback annotation in a shadow file and challenge mypy transfer."""
    if type(timeout) not in (int, float) or not 0 < timeout <= 120:
        raise ValueError("timeout must be between 0 and 120 seconds")
    (
        root,
        source,
        config,
        original,
        mutated,
        expected_code,
        mutation_type,
        selected_kind,
        selected_name,
        ignored_sites,
    ) = _typecheck_inputs(
        root,
        nodeid,
        signature_line,
        transfer_line,
        checker_config,
        signature_kind,
        parameter_name,
    )
    before = _challenge_source_binding(root)
    tool_before, mypy_version = _typecheck_distribution_manifest()
    python_before = _typecheck_python_identity()
    config_sha = hashlib.sha256(_typecheck_read_file(config, 1024 * 1024)).hexdigest()
    evidence = _typecheck_run_phases(root, source, config, original, mutated, timeout)
    return _typecheck_result(
        root,
        nodeid,
        signature_line,
        transfer_line,
        source,
        config,
        original,
        mutated,
        expected_code,
        mutation_type,
        before,
        tool_before,
        mypy_version,
        python_before,
        config_sha,
        evidence,
        signature_kind,
        parameter_name,
        selected_kind,
        selected_name,
        ignored_sites,
    )


def _typecheck_result_state(
    root,
    source,
    config,
    original,
    before,
    tool_before,
    mypy_version,
    python_before,
    config_sha,
    evidence,
    transfer_line,
    expected_code,
):
    after = _challenge_source_binding(root)
    config_stable = (
        config_sha
        == hashlib.sha256(_typecheck_read_file(config, 1024 * 1024)).hexdigest()
    )
    package_after, version_after = _typecheck_distribution_manifest()
    python_after = _typecheck_python_identity()
    input_stable = _typecheck_inputs_stable(source, root, evidence, package_after)
    target_error = bool(evidence["challenge"]) and _typecheck_transfer_matches(
        evidence["challenge"], root, source, transfer_line, expected_code
    )
    stable = (
        before == after
        and config_stable
        and tool_before == package_after
        and mypy_version == version_after
        and python_before == python_after
        and input_stable
        and _typecheck_read_file(source, 4 * 1024 * 1024) == original
    )
    return (
        after,
        package_after,
        config_stable,
        input_stable,
        evidence["baseline_clean"] and target_error and stable,
    )


def _typecheck_result(
    root,
    nodeid,
    signature_line,
    transfer_line,
    source,
    config,
    original,
    mutated,
    expected_code,
    mutation_type,
    before,
    tool_before,
    mypy_version,
    python_before,
    config_sha,
    evidence,
    signature_kind,
    parameter_name,
    selected_kind,
    selected_name,
    ignored_sites,
):
    """Validate run stability and serialize the bounded transfer evidence."""
    after, package_after, config_stable, input_stable, observed = (
        _typecheck_result_state(
            root,
            source,
            config,
            original,
            before,
            tool_before,
            mypy_version,
            python_before,
            config_sha,
            evidence,
            transfer_line,
            expected_code,
        )
    )
    discovery, baseline, challenge = (
        evidence["discovery"],
        evidence["baseline"],
        evidence["challenge"],
    )
    return {
        "schema": "factory.typecheck-transfer-probe.v1",
        "status": "OBSERVED" if observed else "INCOMPLETE",
        "nodeid": nodeid,
        "signature_line": signature_line,
        "transfer_line": transfer_line,
        "mutation_type": mutation_type,
        "signature_kind": selected_kind,
        "parameter_name": selected_name,
        "unrelated_type_ignore_sites": ignored_sites,
        "unrelated_dependency_type_ignore_sites": evidence["dependency_suppressions"],
        "expected_diagnostic": expected_code,
        "mypy_version": mypy_version,
        "config_sha256": config_sha,
        "mypy_distribution_sha256": tool_before,
        "dependency_manifest_sha256": hashlib.sha256(
            json.dumps(evidence["discovered_manifest"], separators=(",", ":")).encode()
        ).hexdigest()
        if evidence["discovered_manifest"]
        else None,
        "python_identity_sha256": python_before,
        "environment_sha256": evidence["environment_sha256"],
        "mutated_source_sha256": hashlib.sha256(mutated).hexdigest(),
        "source_sha256": before,
        "source_unchanged": before == after,
        "config_unchanged": config_stable,
        "checker_unchanged": tool_before == package_after,
        "checker_inputs_stable": input_stable,
        "resolver_stable": evidence["resolver_stable"],
        "resolver_manifest_sha256": evidence["resolver_manifest_sha256"],
        "resolver_entries": evidence["resolver_entries"],
        "resolver_bytes": evidence["resolver_bytes"],
        "search_paths_sha256": evidence["search_paths_sha256"],
        "discovery": _typecheck_phase_report(discovery),
        "baseline": _typecheck_phase_report(baseline) if baseline else {},
        "challenge": _typecheck_phase_report(challenge) if challenge else {},
        "limits": [
            "Local mypy checker transfer evidence only; it does not establish runtime behavior or program correctness",
            "Bounded process supervision is not a sandbox or hidden-descendant proof",
            "Advisory output cannot suppress findings or grant approval or release authority",
            "Unrelated line-local type-ignore statements are inventoried but were not validated",
        ],
    }


def _typecheck_run_valid(facts, output, exit_code=0):
    return (
        isinstance(output, str)
        and facts.get("exit_code") == exit_code
        and facts.get("timed_out") is False
        and facts.get("output_limit_exceeded") is False
        and facts.get("cleanup_confirmed") is True
        and facts.get("launch_error") is False
        and len(output.encode("utf-8")) <= 8 * 1024 * 1024
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
        if args.kind == "typecheck":
            return probe(
                args.root,
                args.nodeid,
                args.signature_line,
                args.transfer_line,
                args.checker_config,
                timeout=args.timeout,
                signature_kind=args.signature_kind,
                parameter_name=args.parameter_name,
            )
        if args.line is None:
            raise ValueError("A source line is required")
        return probe(args.root, args.nodeid, args.line, timeout=args.timeout)
    except (ValueError, OSError):
        return {
            "schema": "factory.probe-validation.v1",
            "status": "INVALID",
            "kind": args.kind,
            "reason": "Probe inputs or source could not be validated; no observation established.",
        }


def _cli_parser():
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Run an explicit local assertion, call, attribute, or mypy transfer probe; "
            "runtime probes execute project code locally."
        )
    )
    parser.add_argument("--root", required=True)
    parser.add_argument("--nodeid", required=True)
    parser.add_argument("--line", type=int)
    parser.add_argument("--signature-line", type=int)
    parser.add_argument("--signature-kind", choices=("parameter", "return"))
    parser.add_argument("--parameter-name")
    parser.add_argument("--transfer-line", type=int)
    parser.add_argument("--checker-config")
    parser.add_argument("--production-path")
    parser.add_argument("--production-symbol")
    parser.add_argument("--python")
    parser.add_argument("--mutation-before")
    parser.add_argument("--mutation-after")
    parser.add_argument("--evidence")
    parser.add_argument(
        "--kind",
        choices=("assertion", "call", "attribute", "typecheck", "production-mutation"),
        default="assertion",
    )
    parser.add_argument("--timeout", type=float, default=30)
    return parser


def _cli_typecheck_args_valid(args):
    return (
        all(
            value is not None
            for value in (args.checker_config, args.signature_line, args.transfer_line)
        )
        and args.line is None
        and (args.parameter_name is None or args.signature_kind == "parameter")
    )


def _cli_selected_probe(args):
    if args.kind == "production-mutation":
        from .runtime_audit_runner import capture_local_production_mutation

        if (
            not all(
                (
                    args.production_path,
                    args.production_symbol,
                    args.mutation_before,
                    args.mutation_after,
                    args.evidence,
                )
            )
            or args.line is None
            or not math.isfinite(args.timeout)
            or not 1 <= args.timeout <= 300
        ):
            return {
                "schema": "factory.probe-validation.v1",
                "status": "INVALID",
                "kind": args.kind,
                "reason": "Production path, symbol, exact before/after text, and evidence path are required.",
            }
        try:
            return capture_local_production_mutation(
                Path(args.root),
                args.nodeid,
                args.line,
                args.production_path,
                args.production_symbol,
                args.mutation_before,
                args.mutation_after,
                args.evidence,
                timeout_seconds=math.ceil(args.timeout),
                python_executable=Path(args.python) if args.python else None,
            )
        except (ValueError, OSError):
            return {
                "schema": "factory.probe-validation.v1",
                "status": "INVALID",
                "kind": args.kind,
                "reason": "Mutation inputs or workspace could not be validated.",
            }
    probe = {
        "assertion": probe_assertion_propagation,
        "call": probe_call_propagation,
        "attribute": probe_attribute_removal,
        "typecheck": probe_typecheck_transfer,
    }[args.kind]
    if args.kind == "typecheck" and not _cli_typecheck_args_valid(args):
        return {
            "schema": "factory.probe-validation.v1",
            "status": "INVALID",
            "kind": args.kind,
            "reason": "Typecheck probes require checker config, signature line, and transfer line.",
        }
    return _probe_cli_result(probe, args)


def main(argv=None):
    """Run one explicitly selected local behavioral or typecheck probe."""
    args = _cli_parser().parse_args(argv)
    result = _cli_selected_probe(args)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "OBSERVED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
